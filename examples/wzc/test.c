#include <stdio.h>
#include "spdk/event.h"// Include the header file that defines struct spdk_app_opts
#include "spdk/bdev.h"  // Include the header file that defines enum spdk_bdev_event_type
#include "spdk/blob_bdev.h"
#include "spdk/blob.h"  // Include the header file that defines struct spdk_blob_store and spdk_bs_init

static void wzc_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *event_ctx) {
    SPDK_NOTICELOG("WZC_cb is invoked!\n");
}

static void wzc_init_complete(void *cb_arg, struct spdk_blob_store *bs, int bserrno) {
    SPDK_NOTICELOG("WZC_init_complete is invoked!\n");
}

static void wzc_func(void *ctx) {
    SPDK_NOTICELOG("Hello, NNSS!\n");

    struct spdk_bs_dev *dev = NULL;
    const char *bdev_name = "Malloc0"; 
    int ret = spdk_bdev_create_bs_dev_ext(bdev_name, wzc_cb, &dev, NULL);
    if (ret) {
        SPDK_ERRLOG("Failed to create wzc blob_bdev!\n");
        spdk_app_stop(-1);
        return;
    }
    spdk_bs_init(dev, NULL, wzc_init_complete, NULL);
}

int main(int argc, char **argv) {
    struct spdk_app_opts opts;
    spdk_app_opts_init(&opts, sizeof(opts));
    opts.name = "test_app";
    opts.json_config_file = argv[1];
    
    spdk_app_start(&opts, wzc_func, NULL);
    return 0;
}