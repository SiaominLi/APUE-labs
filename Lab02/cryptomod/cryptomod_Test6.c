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

#define _BUFFER_SIZE 3072
#define _AES_BLOCK_SIZE 16


static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static DEFINE_MUTEX(crypto_mutex);
static struct crypto_skcipher *tfm;
static struct skcipher_request *req;
// static struct CryptoSetup crypto_config;
// static enum CryptoMode c_mode;

static unsigned long byte_freq[256] = {0};
static size_t total_read = 0;
int all_dev_write = 0;

// static char *device_buffer;
// static char *out_buffer;
// static size_t out_buffer_len;
// static size_t buffer_len = 0;

struct my_device_data {
    char *device_buffer;
    char *out_buffer;
    size_t buffer_len;
    size_t out_buffer_len;
    struct CryptoSetup crypto_config;
    // struct mutex dev_mutex;
};

// AES encrypt
static int encrypt_data(const u8 *input, u8 *output, size_t len) {
    struct scatterlist sg_in, sg_out;
    mutex_lock(&crypto_mutex);
    DECLARE_CRYPTO_WAIT(wait);
    struct skcipher_request *req;

    if (!input || !output) {
        mutex_unlock(&crypto_mutex);
        return -EINVAL;
    }
    req = skcipher_request_alloc(tfm, GFP_KERNEL);

    sg_init_one(&sg_in, input, len);
    sg_init_one(&sg_out, output, len);

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                crypto_req_done, &wait);

    skcipher_request_set_crypt(req, &sg_in, &sg_out, len, NULL);
    mutex_unlock(&crypto_mutex);
    return crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
}

// AES decrypt
static int decrypt_data(const u8 *input, u8 *output, size_t len) {
    struct scatterlist sg_in, sg_out;
    mutex_lock(&crypto_mutex);
    DECLARE_CRYPTO_WAIT(wait);
    struct skcipher_request *req;

    if (!input || !output) {
        mutex_unlock(&crypto_mutex);
        return -EINVAL;
    }
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    sg_init_one(&sg_in, input, len);
    sg_init_one(&sg_out, output, len);

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                    CRYPTO_TFM_REQ_MAY_SLEEP,
                                crypto_req_done, &wait);

    skcipher_request_set_crypt(req, &sg_in, &sg_out, len, NULL);
    mutex_unlock(&crypto_mutex);
    return crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t write_in_len, loff_t *off) {
    struct my_device_data *dev_data = f->private_data;
    if (!dev_data) return -ENODEV;

    // mutex_lock(&crypto_mutex);

    if (write_in_len > _BUFFER_SIZE) {
        // mutex_unlock(&crypto_mutex);
        return -ENOMEM;
    }

    if (copy_from_user(dev_data->device_buffer + dev_data->buffer_len, buf, write_in_len)) {
        // mutex_unlock(&crypto_mutex);
        return -EFAULT;
    }
    printk("write in %d bytes\n", (int)write_in_len);
    dev_data->buffer_len += write_in_len;
    // printk("write data: \n");
    // for(int i=0; i<write_in_len; i++){
    //     printk("i: %d, write_in: %d ",i, *(device_buffer+i));
    // }
    all_dev_write += write_in_len;
    printk("c_mode: %d",dev_data->crypto_config.c_mode);
    if (dev_data->crypto_config.c_mode == 0) {
        printk("ENCing......");
        int remain_len = dev_data->buffer_len % _AES_BLOCK_SIZE;
        int encode_len = dev_data->buffer_len - remain_len;
        encrypt_data(dev_data->device_buffer, dev_data->device_buffer + dev_data->out_buffer_len, encode_len);
        memcpy(dev_data->out_buffer + dev_data->out_buffer_len, dev_data->device_buffer, encode_len);

        dev_data->buffer_len -= encode_len;
        dev_data->out_buffer_len += encode_len;

        memmove(dev_data->device_buffer, dev_data->device_buffer + encode_len, dev_data->buffer_len);
        // mutex_unlock(&crypto_mutex);
    } 
    else if (dev_data->crypto_config.c_mode == 1) {
        printk("DECing......");
        if(dev_data->buffer_len > 32){
            int remain_len = dev_data->buffer_len % _AES_BLOCK_SIZE;
            int decode_len = dev_data->buffer_len - remain_len - _AES_BLOCK_SIZE;
            // cryptomod_encrypt_decrypt(crypto_key, crypto_key_len, input_buffer, decode_len, c_mode == ENC);
            decrypt_data(dev_data->device_buffer, dev_data->device_buffer, decode_len);
            memcpy(dev_data->out_buffer + dev_data->out_buffer_len, dev_data->device_buffer, decode_len); //input -> output

            dev_data->buffer_len -= decode_len;
            dev_data->out_buffer_len += decode_len;

            memmove(dev_data->device_buffer, dev_data->device_buffer + decode_len, dev_data->buffer_len); // move remain buffer
            // buffer_len = write_in_len;
            // mutex_unlock(&crypto_mutex);
        }
        // else mutex_unlock(&crypto_mutex);
    }
    printk("(Write) Remain Buffer len %lu | Out_Buffer len %lu\n", dev_data->buffer_len , dev_data->out_buffer_len);
    
    // mutex_unlock(&crypto_mutex);
    return write_in_len;
}


static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    struct my_device_data *dev_data = f->private_data;
    if (!dev_data) return -ENODEV;
    printk("reading...");
    mutex_lock(&crypto_mutex);
    // printk("(user read dev)");
    // if (*off >= buffer_len) {
    //     mutex_unlock(&crypto_mutex);
    //     return 0; // EOF
    // }
    size_t copylen;

    if (dev_data->crypto_config.c_mode == ENC) copylen = min(len, dev_data->out_buffer_len);
    else copylen = min(len, dev_data->out_buffer_len - *off);
    // printk("out_buffer(read): %d bytes\n", copylen);
    
    // for (size_t i = 0; i < out_buffer_len; i++) {
    //     printk("i:%zu) :=  %x ", i, *(out_buffer + i));
    // }
    // printk("(Read) user req %zu bytes & copy_to_user %zu bytes", len, copylen);

    if (copy_to_user(buf, dev_data->out_buffer + *off, copylen)) {
        mutex_unlock(&crypto_mutex);
        printk(KERN_ERR "copy_to_user failed\n");
        return -EFAULT;
    }
    else {
        if (dev_data->crypto_config.c_mode == ENC) {
            for (size_t i = 0; i < copylen; i++) {
                // printk("(freq map++)");
                byte_freq[(unsigned long)dev_data->out_buffer[i]]++;
            }
        }

        dev_data->out_buffer_len -= copylen;
        memmove(dev_data->out_buffer, dev_data->out_buffer + copylen, dev_data->out_buffer_len);
    }

    total_read += copylen;
    printk("(Read)Dev total read: %lu", total_read);
    // if(*off >= _BUFFER_SIZE) *off = 0;
    // else *off += copylen;
    // printk("buffer offset: %lld", *off);
    mutex_unlock(&crypto_mutex);
    return copylen;
}


static int cryptomod_proc_read(struct seq_file *m, void *v) {
    // printk("user call freq map---------------------------------");
    seq_printf(m, "%zu %d\n", total_read, all_dev_write);

    // if (dev_data->crypto_config.c_mode == ENC) {
    //     for (int i = 0; i < 16; i++) {
    //         for (int j = 0; j < 16; j++) {
    //             seq_printf(m, "%lu ", byte_freq[i * 16 + j]);
    //         }
    //         seq_printf(m, "\n");
    //     }
    // }
    // else{
    //     for (int i = 0; i < 16; i++) {
    //         for (int j = 0; j < 16; j++) {
    //             seq_printf(m, "%d ", 0);
    //         }
    //         seq_printf(m, "\n");
    //     }
    // }
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            seq_printf(m, "%lu ", byte_freq[i * 16 + j]);
        }
        seq_printf(m, "\n");
    }
    
    all_dev_write = 0;
    return 0;
}

static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    struct my_device_data *dev_data = fp->private_data;
    if (!dev_data) return -ENODEV;
    printk("in ioctl....");
    mutex_lock(&crypto_mutex);
    printk("in ioctling....");
    switch (cmd) {
        case CM_IOC_SETUP:
        {
            struct CryptoSetup setup;
            if (copy_from_user(&setup, (struct CryptoSetup __user *)arg, sizeof(setup))){
                mutex_unlock(&crypto_mutex);
                return -EBUSY;
            }
            // printk("(IOC_SETUP) key_len: %d | io_mode: %d, | c_mode: %d", setup.key_len, setup.io_mode, setup.c_mode);
            // printk("copy form user: io: %d, c: %d\n", setup.io_mode, setup.c_mode);

            if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32){
                mutex_unlock(&crypto_mutex);
                return -EINVAL;
            }
            
            memcpy(&dev_data->crypto_config, &setup, sizeof(struct CryptoSetup));
            memset(dev_data->device_buffer, 0, _BUFFER_SIZE);
            dev_data->buffer_len = 0;
            // c_mode = 
            crypto_skcipher_setkey(tfm, dev_data->crypto_config.key, dev_data->crypto_config.key_len);
            mutex_unlock(&crypto_mutex);
            break;
        }

        case CM_IOC_CLEANUP:
            memset(dev_data->device_buffer, 0, _BUFFER_SIZE);
            dev_data->buffer_len = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            total_read = dev_data->out_buffer_len = 0;
            mutex_unlock(&crypto_mutex);
            break;

        case CM_IOC_CNT_RST: 
            total_read = 0;
            dev_data->out_buffer_len = 0;
            memset(byte_freq, 0, sizeof(byte_freq));
            mutex_unlock(&crypto_mutex);
            break;

        case CM_IOC_FINALIZE:
        {
            // struct my_device_data *dev_data = fp->private_data;
            // mutex_lock(&crypto_mutex);
            // printk("called finalize");

            if (dev_data->crypto_config.c_mode == ENC) {
                size_t padding = _AES_BLOCK_SIZE - (dev_data->buffer_len % _AES_BLOCK_SIZE);
                if (dev_data->buffer_len + padding > _BUFFER_SIZE) {
                    mutex_unlock(&crypto_mutex);
                    return -ENOMEM;
                }
                
                memset(dev_data->device_buffer + dev_data->buffer_len, padding, padding);
                
                encrypt_data(dev_data->device_buffer, dev_data->device_buffer, padding);
                dev_data->buffer_len += padding;

                memcpy(dev_data->out_buffer + dev_data->out_buffer_len, dev_data->device_buffer, dev_data->buffer_len); 
                dev_data->out_buffer_len += dev_data->buffer_len;
            } 
            else if (dev_data->crypto_config.c_mode == DEC) {
                if (dev_data->buffer_len % _AES_BLOCK_SIZE != 0) {
                    mutex_unlock(&crypto_mutex);
                    return -EINVAL;
                }
                decrypt_data(dev_data->device_buffer, dev_data->device_buffer, dev_data->buffer_len);
                // size_t padding = device_buffer[buffer_len - 1];
                // if (padding > _AES_BLOCK_SIZE) {
                //     // mutex_unlock(&crypto_mutex);
                //     return -EINVAL;
                // }

                memcpy(dev_data->out_buffer + dev_data->out_buffer_len, dev_data->device_buffer, dev_data->buffer_len); 

                // buffer_len -= padding;
                dev_data->out_buffer_len = dev_data->buffer_len - *(dev_data->device_buffer + dev_data->buffer_len - 1);
            }

            // printk("device_buffer(after padding): \n");
            // for (size_t i = 0; i < buffer_len; i++) {
            //     printk("i: %zu, val: %d ", i, *(device_buffer + i));
            // }

            mutex_unlock(&crypto_mutex);
            break;
        }
        default:
        {
            mutex_unlock(&crypto_mutex);
            return -EINVAL;
        }
    }
    mutex_unlock(&crypto_mutex);
    return 0;
}

static int cryptomod_dev_open(struct inode *inode, struct file *file) {
    struct my_device_data *dev_data;
    
    dev_data = kzalloc(sizeof(struct my_device_data), GFP_KERNEL);
    if (!dev_data) {
        printk(KERN_ERR "cryptomod: Failed to allocate memory for device data\n");
        return -ENOMEM;
    }

    dev_data->device_buffer = kmalloc(_BUFFER_SIZE, GFP_KERNEL);
    if (!dev_data->device_buffer) {
        printk(KERN_ERR "cryptomod: Failed to allocate device_buffer\n");
        kfree(dev_data);
        return -ENOMEM;
    }

    dev_data->out_buffer = kmalloc(_BUFFER_SIZE, GFP_KERNEL);
    if (!dev_data->out_buffer) {
        printk(KERN_ERR "cryptomod: Failed to allocate out_buffer\n");
        kfree(dev_data->device_buffer);
        kfree(dev_data);
        return -ENOMEM;
    }

    dev_data->buffer_len = 0; 
    dev_data->out_buffer_len = 0;
    mutex_init(&crypto_mutex);  

    file->private_data = dev_data;
    return 0;
}

static int cryptomod_dev_release(struct inode *inode, struct file *file) {
    struct my_device_data *dev_data = file->private_data;
    if (dev_data) {
        kfree(dev_data->device_buffer);
        kfree(dev_data->out_buffer);
        kfree(dev_data);
    }
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

    // req = skcipher_request_alloc(tfm, GFP_KERNEL);
    // if (!req) {
    //     printk(KERN_ERR "cryptomod: Failed to allocate skcipher request\n");
    //     ret = -ENOMEM;
    //     goto free_tfm;
    // }

    return 0;

// free_tfm:
//     crypto_free_skcipher(tfm);
del_cdev:
    cdev_del(&c_dev);
destroy_device:
    device_destroy(clazz, devnum);
destroy_class:
    class_destroy(clazz);
unregister_chrdev:
    unregister_chrdev_region(devnum, 1);
free_mem:
    
    return ret;
}


static void __exit cryptomod_cleanup(void)
{
    remove_proc_entry("cryptomod", NULL);
    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    // if (device_buffer) {
    //     kfree(device_buffer);
    //     device_buffer = NULL;
    // }
    // if (out_buffer) {
    //     kfree(out_buffer);
    //     out_buffer = NULL;
    // }

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
