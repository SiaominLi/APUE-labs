#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/scatterlist.h> 
#include <crypto/skcipher.h>
#include "cryptomod.h"

#define BUFFER_SIZE 1024
#define AES_BLOCK_SIZE 16

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
static struct crypto_skcipher *tfm;
static struct skcipher_request *req;
static char *device_buffer;
static size_t buffer_len = 0;
static struct CryptoSetup crypto_config;
static u8 byte_freq[256] = {0};
static size_t total_read = 0, total_write = 0;

int actual_write = 0;
// AES encrypt
static int encrypt_data(const u8 *input, u8 *output, size_t len) {
    struct scatterlist sg_in, sg_out;
    DECLARE_CRYPTO_WAIT(wait);

    if (!input || !output) 
        return -EINVAL;

    sg_init_one(&sg_in, input, len);
    sg_init_one(&sg_out, output, len);

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                crypto_req_done, &wait);

    skcipher_request_set_crypt(req, &sg_in, &sg_out, len, NULL);

    return crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
}

// AES decrypt
static int decrypt_data(const u8 *input, u8 *output, size_t len) {
    struct scatterlist sg_in, sg_out;
    DECLARE_CRYPTO_WAIT(wait);

    if (!input || !output) 
        return -EINVAL;

    sg_init_one(&sg_in, input, len);
    sg_init_one(&sg_out, output, len);

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                crypto_req_done, &wait);

    skcipher_request_set_crypt(req, &sg_in, &sg_out, len, NULL);

    return crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    if (len > BUFFER_SIZE) return -ENOMEM;

    char *plaintext = kmalloc(len, GFP_KERNEL);
    if (!plaintext) return -ENOMEM;
    if (copy_from_user(plaintext, buf, len)) {
        kfree(plaintext);
        return -EFAULT;
    }

    for(int j=0; j< len; j++){
        *(device_buffer + total_write + j) = *(plaintext + j);
    }
    total_write += len;

    buffer_len = total_write;
    actual_write += len;
    printk("write in len: %d\n", (int)len);
    // printk("actual_write: %d\n", actual_write);
    // printk("plaintext: \n");
    // for(int i=0; i<len; i++){
    //     printk("i: %d, val_plain: %d ",i, *(plaintext+i));
    // }
    // printk("\n");

    // // 加密
    // encrypt_data(plaintext, device_buffer + total_write, buffer_len);
    // printk("device_buffer: \n");
    // for(int i=0; i<(buffer_len); i++){
    //     printk("i: %d, val: %d ",i, *(device_buffer+i+total_write));
    // }
    // printk("\n");
    
    // total_write += buffer_len;
    // printk("total write: %d", (int) total_write);

    kfree(plaintext);
    return len;
}

// `read()` - 回傳加密後的數據，並統計 byte 頻率
static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    if (*off >= buffer_len) return 0; // EOF
    printk("called read freq");

    size_t copylen = min(len, buffer_len - *off);
    // size_t copylen = buffer_len;
    // printk("copylen: %d", (int)copylen);

    if (copy_to_user(buf, device_buffer + *off, copylen)) return -EFAULT;
    if (crypto_config.c_mode == ENC) {
        for (size_t i = 0; i < copylen; i++) {
            byte_freq[(unsigned char)device_buffer[*off + i]]++;
        }
    }
    total_read += copylen;

    *off += copylen;
    total_write = 0;
    return copylen;
}

// `/proc/cryptomod` 讀取函數
static int cryptomod_proc_read(struct seq_file *m, void *v) {
    seq_printf(m, "%zu %d\n", total_read, actual_write);
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            seq_printf(m, "%d ", byte_freq[i * 16 + j]);
        }
        seq_printf(m, "\n");
    }
    actual_write = 0;
    return 0;
}

static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case CM_IOC_SETUP:
        {
            struct CryptoSetup setup;
            if (copy_from_user(&setup, (struct CryptoSetup __user *)arg, sizeof(setup))){
                return -EBUSY;
            }
            // printk("copy form user: %d\n", setup.key_len);
            // printk("copy form user: io: %d, c: %d\n", setup.io_mode, setup.c_mode);

            if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32)
                return -EINVAL;

            memcpy(&crypto_config, &setup, sizeof(struct CryptoSetup));
            memset(device_buffer, 0, BUFFER_SIZE);
            buffer_len = 0;

            crypto_skcipher_setkey(tfm, crypto_config.key, crypto_config.key_len);
            break;
        }

        case CM_IOC_CLEANUP:
            memset(device_buffer, 0, BUFFER_SIZE);
            buffer_len = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            total_read = total_write = 0;
            break;

        case CM_IOC_CNT_RST: 
            total_read = 0;
            total_write = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            break;

        case CM_IOC_FINALIZE:
            printk("called finalize");
            if (crypto_config.c_mode == ENC) {
                size_t padding = AES_BLOCK_SIZE - (buffer_len % AES_BLOCK_SIZE);
                if (buffer_len + padding > BUFFER_SIZE) return -ENOMEM;
                memset(device_buffer + buffer_len, padding, padding);
                // actual_write += buffer_len;
                buffer_len += padding;
                // for(int i =0; i< total_write; i++){
                //     printk("i: %d, val: %d ",i, *(device_buffer+i));
                // }
                encrypt_data(device_buffer, device_buffer, buffer_len);
            } 
            else if (crypto_config.c_mode == DEC) {
                decrypt_data(device_buffer, device_buffer, buffer_len);
                // printk("device_buffer(before): \n");
                // for(int i=0; i<(buffer_len); i++){
                //     printk("i: %d, val: %d ",i, *(device_buffer+i));
                // }
                // printk("\n");
                if (buffer_len % AES_BLOCK_SIZE != 0) return -EINVAL;
                size_t padding = device_buffer[buffer_len - 1];
                if (padding > AES_BLOCK_SIZE) return -EINVAL;
                buffer_len -= padding;

            }

            
            // printk("device_buffer(after): \n");
            // for(int i=0; i<(buffer_len); i++){
            //     printk("i: %d, val: %d ",i, *(device_buffer+i));
            // }
            // printk("\n");

            break;

        default:
            return -EINVAL;
    }
    return 0;
}


static const struct file_operations cryptomod_dev_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = cryptomod_dev_read,
    .write = cryptomod_dev_write,
    .unlocked_ioctl = cryptomod_dev_ioctl
};

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
    .proc_open = cryptomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init cryptomod_init(void)
{
    device_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!device_buffer) return -ENOMEM;

    alloc_chrdev_region(&devnum, 0, 1, "cryptodev");
    clazz = class_create("cryptoclass");
    device_create(clazz, NULL, devnum, NULL, "cryptodev");
    cdev_init(&c_dev, &cryptomod_dev_fops);
    cdev_add(&c_dev, devnum, 1);

    proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    // crypto_skcipher_setkey(tfm, crypto_config.key, 16);  // 預設 16 bytes

    return 0;
}

static void __exit cryptomod_cleanup(void)
{
    remove_proc_entry("cryptomod", NULL);
    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);
    kfree(device_buffer);
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);
MODULE_LICENSE("GPL");
