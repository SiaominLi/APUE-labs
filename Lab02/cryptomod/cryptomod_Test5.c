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
#include <linux/mutex.h>
#include "cryptomod.h"

#define _BUFFER_SIZE 5120
#define _AES_BLOCK_SIZE 16


static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static DEFINE_MUTEX(crypto_mutex);
static struct crypto_skcipher *tfm;
static struct skcipher_request *req;
static struct CryptoSetup crypto_config;

static unsigned long byte_freq[256] = {0};
static size_t total_read = 0;

static char *device_buffer;
static char *out_buffer;
static size_t out_buffer_len;
static size_t buffer_len = 0;

int all_dev_write = 0;
u8 FINALIZE_flag = 0;

// struct my_device_data {
//     char *device_buffer;
//     size_t buffer_len;
//     // size_t total_read;
//     size_t out_buffer_len;
// };

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

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t write_in_len, loff_t *off) {
    // struct my_device_data *dev_data = f->private_data;
    // mutex_lock(&crypto_mutex);

    if (write_in_len + buffer_len > _BUFFER_SIZE) {
        // mutex_unlock(&crypto_mutex);
        return -EAGAIN;
    }
    if (FINALIZE_flag) {
        // mutex_unlock(&crypto_mutex);
        return -EINVAL;
    }

    if (crypto_config.key_len != 16 && crypto_config.key_len != 24 && crypto_config.key_len != 32)
        return -EINVAL;

    if (copy_from_user(device_buffer + buffer_len, buf, write_in_len)) {
        // mutex_unlock(&crypto_mutex);
        return -EBUSY;
    }
    // printk("write in %d bytes\n", (int)write_in_len);
    buffer_len += write_in_len;
    // printk("write data: \n");
    // for(int i=0; i<write_in_len; i++){
    //     printk("i: %d, write_in: %d ",i, *(device_buffer+i));
    // }
    all_dev_write += write_in_len;
    
        ////modify here////
    if (crypto_config.c_mode == ENC) {
        int remain_len = buffer_len % _AES_BLOCK_SIZE;
        int encode_len = buffer_len - remain_len;
        encrypt_data(device_buffer, device_buffer + out_buffer_len, encode_len);
        memcpy(out_buffer + out_buffer_len, device_buffer, encode_len);

        buffer_len -= encode_len;
        out_buffer_len += encode_len;

        memmove(device_buffer, device_buffer + encode_len, buffer_len);
    } 
    else if (crypto_config.c_mode == DEC) {
        if(buffer_len > 32){
            int remain_len = buffer_len % _AES_BLOCK_SIZE;
            int decode_len = buffer_len - remain_len - _AES_BLOCK_SIZE;
            // cryptomod_encrypt_decrypt(crypto_key, crypto_key_len, input_buffer, decode_len, c_mode == ENC);
            decrypt_data(device_buffer, device_buffer, decode_len);
            memcpy(out_buffer + out_buffer_len, device_buffer, decode_len); //input -> output

            buffer_len -= decode_len;
            out_buffer_len += decode_len;

            memmove(device_buffer, device_buffer + decode_len, buffer_len); // move remain buffer
            // buffer_len = write_in_len;
        }
    }
    // printk("(Write) Remain Buffer len %lu | Out_Buffer len %lu\n", buffer_len , out_buffer_len);
    
    // printk("out_buffer: \n");
    // for(int i=0; i<(out_buffer_len); i++){
    //     printk("i) %d := %d ",i, *(out_buffer+i));
    // }
    
    // printk("(Write)Dev total write: %d", all_dev_write);
    // out_buffer_len += write_in_len;
    
    // mutex_unlock(&crypto_mutex);
    return write_in_len;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    // struct my_device_data *dev_data = f->private_data;
    // mutex_lock(&crypto_mutex);
    // printk("(user read dev)");
    // if (*off >= buffer_len) {
    //     mutex_unlock(&crypto_mutex);
    //     return 0; // EOF
    // }
    size_t copylen;
    if (crypto_config.key_len != 16 && crypto_config.key_len != 24 && crypto_config.key_len != 32)
        return -EINVAL;
    
    if (FINALIZE_flag) {
        // mutex_unlock(&crypto_mutex);
        return -EINVAL;
    }

    if (crypto_config.c_mode == ENC) copylen = min(len, out_buffer_len);
    else copylen = min(len, out_buffer_len - *off);
    // printk("out_buffer(read): %d bytes\n", copylen);
    
    // for (size_t i = 0; i < out_buffer_len; i++) {
    //     printk("i:%zu) :=  %x ", i, *(out_buffer + i));
    // }
    // printk("(Read) user req %zu bytes & copy_to_user %zu bytes", len, copylen);

    if (copy_to_user(buf, out_buffer + *off, copylen)) {
        // mutex_unlock(&crypto_mutex);
        printk(KERN_ERR "copy_to_user failed\n");
        return -EFAULT;
    }
    else {
        if (crypto_config.c_mode == ENC) {
            for (size_t i = 0; i < copylen; i++) {
                // printk("(freq map++)");
                byte_freq[(unsigned long)out_buffer[i]]++;
            }
        }

        out_buffer_len -= copylen;
        memmove(out_buffer, out_buffer + copylen, out_buffer_len);
    }


    

    total_read += copylen;
    // printk("(Read)Dev total read: %lu", total_read);
    // if(*off >= _BUFFER_SIZE) *off = 0;
    // else *off += copylen;
    // printk("buffer offset: %lld", *off);
    // mutex_unlock(&crypto_mutex);
    return copylen;
}

// `/proc/cryptomod` 讀取函數
static int cryptomod_proc_read(struct seq_file *m, void *v) {
    // printk("user call freq map---------------------------------");
    seq_printf(m, "%zu %d\n", total_read, all_dev_write);

    if (crypto_config.c_mode == ENC) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                seq_printf(m, "%lu ", byte_freq[i * 16 + j]);
            }
            seq_printf(m, "\n");
        }
    }
    else{
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                seq_printf(m, "%d ", 0);
            }
            seq_printf(m, "\n");
        }
    }
    // for (int i = 0; i < 16; i++) {
    //     for (int j = 0; j < 16; j++) {
    //         printk("%d ", byte_freq[i * 16 + j]);
    //     }
    //     printk("\n");
    // }
    
    all_dev_write = 0;
    return 0;
}

static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    // struct my_device_data *dev_data = fp->private_data;
    switch (cmd) {
        case CM_IOC_SETUP:
        {
            struct CryptoSetup setup;
            if(!arg){
                // mutex_unlock(&crypto_mutex);
                return -EINVAL;
            }
            if (copy_from_user(&setup, (struct CryptoSetup __user *)arg, sizeof(setup))){
                return -EBUSY;
            }
            // printk("(IOC_SETUP) key_len: %d | io_mode: %d, | c_mode: %d", setup.key_len, setup.io_mode, setup.c_mode);
            // printk("copy form user: io: %d, c: %d\n", setup.io_mode, setup.c_mode);

            if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32)
                return -EINVAL;

            if (setup.c_mode != 0 && setup.c_mode != 1){
                // mutex_unlock(&crypto_mutex);
                return -EINVAL;
            }
            if (setup.io_mode != 0 && setup.io_mode != 1){
                // mutex_unlock(&crypto_mutex);
                return -EINVAL;
            }

            memcpy(&crypto_config, &setup, sizeof(struct CryptoSetup));
            memset(device_buffer, 0, _BUFFER_SIZE);
            buffer_len = 0;
            FINALIZE_flag = 0;

            crypto_skcipher_setkey(tfm, crypto_config.key, crypto_config.key_len);
            break;
        }

        case CM_IOC_CLEANUP:
            memset(device_buffer, 0, _BUFFER_SIZE);
            buffer_len = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            total_read = out_buffer_len = 0;
            FINALIZE_flag = 0;
            break;

        case CM_IOC_CNT_RST: 
            total_read = 0;
            out_buffer_len = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            break;

        case CM_IOC_FINALIZE:
        {
            // struct my_device_data *dev_data = fp->private_data;
            // mutex_lock(&crypto_mutex);
            // printk("called finalize");
            if (buffer_len == 0) {
                FINALIZE_flag = 1;
                // mutex_unlock(&crypto_mutex);
                return -EINVAL;
            }
            if (crypto_config.c_mode == ENC) {
                size_t padding = _AES_BLOCK_SIZE - (buffer_len % _AES_BLOCK_SIZE);
                if (buffer_len + padding > _BUFFER_SIZE) {
                    // mutex_unlock(&crypto_mutex);
                    return -ENOMEM;
                }
                
                memset(device_buffer + buffer_len, padding, padding);
                
                encrypt_data(device_buffer, device_buffer, padding);
                buffer_len += padding;

                memcpy(out_buffer + out_buffer_len, device_buffer, buffer_len); 
                out_buffer_len += buffer_len;
            } 
            else if (crypto_config.c_mode == DEC) {
                if (buffer_len % _AES_BLOCK_SIZE != 0) {
                    // mutex_unlock(&crypto_mutex);
                    return -EINVAL;
                }
                decrypt_data(device_buffer, device_buffer, buffer_len);
                // size_t padding = device_buffer[buffer_len - 1];
                // if (padding > _AES_BLOCK_SIZE) {
                //     // mutex_unlock(&crypto_mutex);
                //     return -EINVAL;
                // }
                if(*(device_buffer + buffer_len - 1) > _AES_BLOCK_SIZE){
                    // mutex_unlock(&crypto_mutex);
                    return -EINVAL;
                }
                memcpy(out_buffer + out_buffer_len, device_buffer, buffer_len); 

                // buffer_len -= padding;
                out_buffer_len = buffer_len - *(device_buffer + buffer_len - 1);
            }
            FINALIZE_flag = 1;
            // printk("device_buffer(after padding): \n");
            // for (size_t i = 0; i < buffer_len; i++) {
            //     printk("i: %zu, val: %d ", i, *(device_buffer + i));
            // }

            // mutex_unlock(&crypto_mutex);
            break;
        }
        default:
            return -EINVAL;
    }
    return 0;
}
static int cryptomod_dev_open(struct inode *inode, struct file *file) {
    // struct my_device_data *dev_data;

    // device_buffer = kmalloc(_BUFFER_SIZE, GFP_KERNEL);
    // if (!device_buffer) {
    //     kfree(device_buffer);
    //     return -ENOMEM;
    // }

    // out_buffer = kmalloc(_BUFFER_SIZE, GFP_KERNEL);
    // if (!out_buffer) {
    //     kfree(out_buffer);
    //     return -ENOMEM;
    // }

    // // file->private_data = dev_data; 
    // return 0;
    if (!device_buffer || !out_buffer) {
        printk(KERN_ERR "cryptomod: Memory not allocated\n");
        return -ENOMEM;
    }
    return 0;
}
static int cryptomod_dev_release(struct inode *inode, struct file *file) {
    // struct my_device_data *dev_data = file->private_data;

    // if (device_buffer) kfree(device_buffer);
    // if (out_buffer) kfree(out_buffer);

    return 0;
}

static const struct file_operations cryptomod_dev_fops = {
    .owner = THIS_MODULE,
    .open = cryptomod_dev_open,
    .read = cryptomod_dev_read,
    .write = cryptomod_dev_write,
    .unlocked_ioctl = cryptomod_dev_ioctl,
    .release = cryptomod_dev_release
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
    int ret;

    device_buffer = kmalloc(_BUFFER_SIZE, GFP_KERNEL);
    if (!device_buffer) {
        printk(KERN_ERR "cryptomod: Failed to allocate device_buffer\n");
        return -ENOMEM;
    }

    out_buffer = kmalloc(_BUFFER_SIZE, GFP_KERNEL);
    if (!out_buffer) {
        printk(KERN_ERR "cryptomod: Failed to allocate out_buffer\n");
        kfree(device_buffer);
        return -ENOMEM;
    }

    ret = alloc_chrdev_region(&devnum, 0, 1, "cryptodev");
    if (ret < 0) {
        printk(KERN_ERR "cryptomod: Failed to allocate chrdev\n");
        goto free_mem;
    }

    clazz = class_create("cryptoclass");
    if (IS_ERR(clazz)) {
        printk(KERN_ERR "cryptomod: Failed to create class\n");
        ret = PTR_ERR(clazz);
        goto unregister_chrdev;
    }

    if (!device_create(clazz, NULL, devnum, NULL, "cryptodev")) {
        printk(KERN_ERR "cryptomod: Failed to create device\n");
        ret = -ENOMEM;
        goto destroy_class;
    }

    cdev_init(&c_dev, &cryptomod_dev_fops);
    ret = cdev_add(&c_dev, devnum, 1);
    if (ret < 0) {
        printk(KERN_ERR "cryptomod: Failed to add cdev\n");
        goto destroy_device;
    }

    proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "cryptomod: Failed to allocate skcipher\n");
        ret = PTR_ERR(tfm);
        goto del_cdev;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk(KERN_ERR "cryptomod: Failed to allocate skcipher request\n");
        ret = -ENOMEM;
        goto free_tfm;
    }

    return 0;

free_tfm:
    crypto_free_skcipher(tfm);
del_cdev:
    cdev_del(&c_dev);
destroy_device:
    device_destroy(clazz, devnum);
destroy_class:
    class_destroy(clazz);
unregister_chrdev:
    unregister_chrdev_region(devnum, 1);
free_mem:
    kfree(device_buffer);
    kfree(out_buffer);
    return ret;
}


static void __exit cryptomod_cleanup(void)
{
    remove_proc_entry("cryptomod", NULL);
    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    if (device_buffer) {
        kfree(device_buffer);
        device_buffer = NULL;
    }
    if (out_buffer) {
        kfree(out_buffer);
        out_buffer = NULL;
    }

    if (req) {
        skcipher_request_free(req);
        req = NULL;
    }
    if (tfm) {
        crypto_free_skcipher(tfm);
        tfm = NULL;
    }
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);
MODULE_LICENSE("GPL");
