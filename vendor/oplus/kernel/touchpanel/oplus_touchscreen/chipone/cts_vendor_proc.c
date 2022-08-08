#define LOG_TAG         "Vendor"

#include "cts_config.h"
#include "cts_platform.h"
#include "cts_core.h"
#include "cts_test.h"
#include "cts_firmware.h"
#include "cts_strerror.h"
#include "../touchpanel_common.h"

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

/* /proc/touchpanel */
#define PROC_TOUCHPANEL_DIR_NAME    "touchpanel"
#define PROC_TOUCHPANEL_DIR_PATH    "/proc/"PROC_TOUCHPANEL_DIR_NAME

#define PROC_BASELINE_TEST_FILENAME "baseline_test"
#define PROC_BASELINE_TEST_FILEPATH \
    PROC_TOUCHPANEL_DIR_PATH"/"PROC_BASELINE_TEST_FILENAME

#define TEST_DATA_DIR                   "/sdcard/chipone-tddi/test/"
#define RAWDATA_TEST_DATA_FILEPATH      TEST_DATA_DIR"rawdata.csv"
#define NOISE_TEST_DATA_FILEPATH        TEST_DATA_DIR"noise.csv"
#define OPEN_TEST_DATA_FILEPATH         TEST_DATA_DIR"open.csv"
#define SHORT_TEST_DATA_FILEPATH        TEST_DATA_DIR"short.csv"
#define COMP_CAP_TEST_DATA_FILEPATH     TEST_DATA_DIR"compensate_cap.csv"

#define RAWDATA_TEST_DATA_FILEPATH_OK      TEST_DATA_DIR"rawdata-OK-%04d%02d%02d-%02d%02d%02d.csv"
#define RAWDATA_TEST_DATA_FILEPATH_FAIL    TEST_DATA_DIR"rawdata-FAIL-%04d%02d%02d-%02d%02d%02d.csv"
#define NOISE_TEST_DATA_FILEPATH_OK        TEST_DATA_DIR"noise-OK-%04d%02d%02d-%02d%02d%02d.csv"
#define NOISE_TEST_DATA_FILEPATH_FAIL      TEST_DATA_DIR"noise-FAIL-%04d%02d%02d-%02d%02d%02d.csv"
#define OPEN_TEST_DATA_FILEPATH_OK         TEST_DATA_DIR"open-OK-%04d%02d%02d-%02d%02d%02d.csv"
#define OPEN_TEST_DATA_FILEPATH_FAIL       TEST_DATA_DIR"open-FAIL-%04d%02d%02d-%02d%02d%02d.csv"
#define SHORT_TEST_DATA_FILEPATH_OK        TEST_DATA_DIR"short-OK-%04d%02d%02d-%02d%02d%02d.csv"
#define SHORT_TEST_DATA_FILEPATH_FAIL      TEST_DATA_DIR"short-FAIL-%04d%02d%02d-%02d%02d%02d.csv"
#define COMP_CAP_TEST_DATA_FILEPATH_OK     TEST_DATA_DIR"compensate_cap-OK-%04d%02d%02d-%02d%02d%02d.csv"
#define COMP_CAP_TEST_DATA_FILEPATH_FAIL   TEST_DATA_DIR"compensate_cap-FAIL-%04d%02d%02d-%02d%02d%02d.csv"


extern struct touchpanel_data *tsdata;
struct cts_vendor_data {
#ifdef CONFIG_PROC_FS
    /* Baseline test(Screen ON) parameter */
    bool test_reset_pin;
    int  reset_pin_test_result;

    bool test_int_pin;
    int  int_pin_test_result;

    bool test_rawdata;
    u32  rawdata_test_frames;
    int  rawdata_test_result;
    int  rawdata_min;
    int  rawdata_max;
    void *rawdata_test_data;
    int  rawdata_test_data_buf_size;
    int  rawdata_test_data_size;
	char *rawdata_data_filepath;

    bool test_noise;
    u32  noise_test_frames;
    int  noise_test_result;
    int  noise_max;
    void *noise_test_data;
    int  noise_test_data_buf_size;
    int  noise_test_data_size;
	char *noise_data_filepath;

    bool test_open;
    int  open_test_result;
    int  open_min;
    void *open_test_data;
    int  open_test_data_buf_size;
    int  open_test_data_size;
	char *open_data_filepath;

    bool test_short;
    int  short_test_result;
    int  short_min;
    void *short_test_data;
    int  short_test_data_buf_size;
    int  short_test_data_size;
	char *short_data_filepath;

    bool test_comp_cap;
    int  comp_cap_test_result;
    int  comp_cap_min;
    int  comp_cap_max;
    void *comp_cap_test_data;
    int  comp_cap_test_data_buf_size;
    int  comp_cap_test_data_size;
	char *comp_cap_data_filepath;

#endif

    struct chipone_ts_data *cts_data;
};

#ifdef CONFIG_PROC_FS
#define ALLOC_TEST_DATA_MEM(type, size) \
    do { \
        if (vdata->test_##type) { \
            if (vdata->type##_test_data == NULL) { \
                cts_info("- Alloc " #type " test data mem size %d", size); \
                vdata->type##_test_data = vmalloc(size); \
                if (vdata->type##_test_data == NULL) { \
                    cts_err("Alloc " #type " test data mem failed"); \
                    return -ENOMEM; \
                } \
                vdata->type##_test_data_size = size; \
            } \
            memset(vdata->type##_test_data, 0, size); \
        } \
    } while (0)

#define FREE_TEST_DATA_MEM(type) \
    do { \
        if (vdata->type##_test_data) { \
            cts_info("- Free " #type " test data mem"); \
            vfree(vdata->type##_test_data); \
            vdata->type##_test_data = NULL; \
        } \
    } while(0)

static int alloc_baseline_test_data_mem(struct cts_vendor_data *vdata, int nodes)
{
    cts_info("Alloc baseline test data mem");

    ALLOC_TEST_DATA_MEM(rawdata,
        nodes * 2 * vdata->rawdata_test_frames);
    ALLOC_TEST_DATA_MEM(noise,
        nodes * 2 * vdata->noise_test_frames + 1);
    ALLOC_TEST_DATA_MEM(open, nodes * 2);
    ALLOC_TEST_DATA_MEM(short, nodes * 2 * 7);
    ALLOC_TEST_DATA_MEM(comp_cap, nodes);

    return 0;
}

static void free_baseline_test_data_mem(struct cts_vendor_data *vdata)
{
    cts_info("Free baseline test data mem");

    FREE_TEST_DATA_MEM(rawdata);
    FREE_TEST_DATA_MEM(noise);
    FREE_TEST_DATA_MEM(open);
    FREE_TEST_DATA_MEM(short);
    FREE_TEST_DATA_MEM(comp_cap);
}

#undef ALLOC_TEST_DATA_MEM
#undef FREE_TEST_DATA_MEM

static int dump_touch_data_row_to_buffer(char *buf, size_t size, const void *data,
    int cols, const char *prefix, const char *suffix, char seperator)
{
    int c, count = 0;

    if (prefix) {
        count += scnprintf(buf, size, "%s", prefix);
    }

    for (c = 0; c < cols; c++) {
        count += scnprintf(buf + count, size - count,
            "%4d%c ", ((s16 *)data)[c], seperator);
    }

    if (suffix) {
        count += scnprintf(buf + count, size - count, "%s", suffix);
    }

    return count;
}

static int dump_touch_data_to_csv_file(const char *filepath,
    const void *data, int frames, int rows, int cols)
{
    struct file *file;
    int r, ret = 0;
    loff_t pos = 0;

    cts_info("Dump touch data to csv file: '%s' frames: %u row: %d col: %d",
        filepath, frames, rows, cols);

    file = filp_open(filepath, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(file)) {
        cts_err("Open file '%s' failed %ld(%s)", filepath,
            PTR_ERR(file), cts_strerror((int)PTR_ERR(file)));
        return PTR_ERR(file);
    }

    while (frames--) {
        for (r = 0; r < rows; r++) {
            char linebuf[256];
            int len;

            len = dump_touch_data_row_to_buffer(linebuf,
                sizeof(linebuf), data, cols, NULL, "\n", ',');
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
            ret = kernel_write(file, linebuf, len, &pos);
#else
            ret = kernel_write(file, linebuf, len, pos);
            pos += len;
#endif
            if (ret != len) {
                cts_err("Write to file '%s' failed %d(%s)",
                    filepath, ret, cts_strerror(ret));
                ret = -EIO;
                goto close_file;
            }

            data += cols * 2;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        ret = kernel_write(file, "\n", 1, &pos);
#else
        ret = kernel_write(file, "\n", 1, pos);
        pos ++;
#endif
        if (ret != 1) {
            cts_err("Write newline to file '%s' failed %d(%s)",
                filepath, ret, cts_strerror(ret));
            ret = -EIO;
            goto close_file;
        }
    }

close_file: {
        int r = filp_close(file, NULL);
        if (r) {
            cts_err("Close file '%s' failed %d(%s)",
                filepath, ret, cts_strerror(ret));
        }
    }

    return ret;
}

static void dump_touch_data_to_seq_file(struct seq_file *m,
    const void *data, int rows, int cols)
{
    int r;

    for (r = 0; r < rows; r++) {
        char linebuf[256];
        int len;

        len = dump_touch_data_row_to_buffer(linebuf, sizeof(linebuf),
            data, cols, NULL, "\n", ',');
        seq_puts(m, linebuf);

        data += cols * 2;
    }
}

static int dump_comp_cap_row_to_buffer(char *buf, size_t size, const u8 *cap,
    int cols, const char *prefix, const char *suffix, char seperator)
{
    int c, count = 0;

    if (prefix) {
        count += scnprintf(buf, size, "%s", prefix);
    }

    for (c = 0; c < cols; c++) {
        count += scnprintf(buf + count, size - count,
            "%3u%c ", cap[c], seperator);
    }

    if (suffix) {
        count += scnprintf(buf + count, size - count, "%s", suffix);
    }

    return count;
}

static int dump_comp_cap_to_csv_file(const char *filepath,
    const u8 *cap, int rows, int cols)
{
    struct file *file;
    int r, ret = 0;
    loff_t pos = 0;

    cts_info("Dump compensate cap to csv file: '%s' row: %d col: %d",
        filepath, rows, cols);

    file = filp_open(filepath, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(file)) {
        cts_err("Open file '%s' failed %ld(%s)", filepath,
            PTR_ERR(file), cts_strerror((int)PTR_ERR(file)));
        return PTR_ERR(file);
    }

    for (r = 0; r < rows; r++) {
        char linebuf[256];
        int len;

        len = dump_comp_cap_row_to_buffer(linebuf, sizeof(linebuf),
            cap, cols, NULL, "\n", ',');
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        ret = kernel_write(file, linebuf, len, &pos);
#else
        ret = kernel_write(file, linebuf, len, pos);
        pos += len;
#endif
        if (ret != len) {
            cts_err("Write to file '%s' failed %d(%s)",
                filepath, ret, cts_strerror(ret));
            goto close_file;
        }

        cap += cols;
    }

close_file: {
        int r = filp_close(file, NULL);
        if (r) {
            cts_err("Close file '%s' failed %d(%s)",
                filepath, ret, cts_strerror(ret));
        }
    }

    return ret;
}

static void dump_comp_cap_to_seq_file(struct seq_file *m,
    const u8 *data, int rows, int cols)
{
    int r;

    for (r = 0; r < rows; r++) {
        char linebuf[256];
        int len;

        len = dump_comp_cap_row_to_buffer(linebuf, sizeof(linebuf),
            data, cols, NULL, "\n", ',');
        seq_puts(m, linebuf);

        data += cols;
    }
}

static int save_baseline_test_data_to_file(struct cts_vendor_data *vdata)
{
	struct timespec now_time;
    struct rtc_time rtc_now_time;
	char file_path[256];
    int rows, cols;
    int ret;

    cts_info("Save baseline test data to file");
	
	getnstimeofday(&now_time);
    rtc_time_to_tm(now_time.tv_sec, &rtc_now_time);
	
	rows  = vdata->cts_data->cts_dev.fwdata.rows;
    cols  = vdata->cts_data->cts_dev.fwdata.cols;
	
	ret = cts_mkdir_for_file(TEST_DATA_DIR, 0777);
	if (ret) {
		cts_err("Create %s failed %d", TEST_DATA_DIR, ret);
		return ret;
	}
    	
	snprintf(file_path, sizeof(file_path), vdata->rawdata_test_result 
			? RAWDATA_TEST_DATA_FILEPATH_FAIL : RAWDATA_TEST_DATA_FILEPATH_OK,
            (rtc_now_time.tm_year + 1900), rtc_now_time.tm_mon + 1, rtc_now_time.tm_mday,
            rtc_now_time.tm_hour, rtc_now_time.tm_min, rtc_now_time.tm_sec);
	vdata->rawdata_data_filepath = kstrdup(file_path, GFP_KERNEL);
	snprintf(file_path, sizeof(file_path), vdata->noise_test_result
			? NOISE_TEST_DATA_FILEPATH_FAIL : NOISE_TEST_DATA_FILEPATH_OK,
            (rtc_now_time.tm_year + 1900), rtc_now_time.tm_mon + 1, rtc_now_time.tm_mday,
            rtc_now_time.tm_hour, rtc_now_time.tm_min, rtc_now_time.tm_sec);
	vdata->noise_data_filepath = kstrdup(file_path, GFP_KERNEL);
	snprintf(file_path, sizeof(file_path), vdata->open_test_result
			? OPEN_TEST_DATA_FILEPATH_FAIL : OPEN_TEST_DATA_FILEPATH_OK,
            (rtc_now_time.tm_year + 1900), rtc_now_time.tm_mon + 1, rtc_now_time.tm_mday,
            rtc_now_time.tm_hour, rtc_now_time.tm_min, rtc_now_time.tm_sec);
	vdata->open_data_filepath = kstrdup(file_path, GFP_KERNEL);
	snprintf(file_path, sizeof(file_path), vdata->short_test_result
			? SHORT_TEST_DATA_FILEPATH_FAIL : SHORT_TEST_DATA_FILEPATH_OK,
            (rtc_now_time.tm_year + 1900), rtc_now_time.tm_mon + 1, rtc_now_time.tm_mday,
            rtc_now_time.tm_hour, rtc_now_time.tm_min, rtc_now_time.tm_sec);
	vdata->short_data_filepath = kstrdup(file_path, GFP_KERNEL);
	snprintf(file_path, sizeof(file_path), vdata->comp_cap_test_result
			? COMP_CAP_TEST_DATA_FILEPATH_FAIL : COMP_CAP_TEST_DATA_FILEPATH_OK,
            (rtc_now_time.tm_year + 1900), rtc_now_time.tm_mon + 1, rtc_now_time.tm_mday,
            rtc_now_time.tm_hour, rtc_now_time.tm_min, rtc_now_time.tm_sec);
	vdata->comp_cap_data_filepath = kstrdup(file_path, GFP_KERNEL);

	if (vdata->test_rawdata) {
        cts_info(" - Save rawdata test data to file");
        ret = dump_touch_data_to_csv_file(
            vdata->rawdata_data_filepath, vdata->rawdata_test_data,
            vdata->rawdata_test_frames, rows, cols);
        if (ret < 0) {
            cts_err("Dump rawdata test data to file failed %d(%s)",
                ret, cts_strerror(ret));
            return ret;
        }
    }

    if (vdata->test_noise) {
        cts_info(" - Save noise test data to file");
        ret = dump_touch_data_to_csv_file(
            vdata->noise_data_filepath, vdata->noise_test_data,
            vdata->noise_test_frames, rows, cols);
        if (ret < 0) {
            cts_err("Dump noise test data to file failed %d(%s)",
                ret, cts_strerror(ret));
            return ret;
        }
    }

    if (vdata->test_open) {
        cts_info(" - Save open test data to file");
        ret = dump_touch_data_to_csv_file(
            vdata->open_data_filepath, vdata->open_test_data,
            1, rows, cols);
        if (ret < 0) {
            cts_err("Dump open test data to file failed %d(%s)",
                ret, cts_strerror(ret));
            return ret;
        }
    }

    if (vdata->test_short) {
        cts_info(" - Save short test data to file");
        ret = dump_touch_data_to_csv_file(
            vdata->short_data_filepath, vdata->short_test_data,
            7, rows, cols);
        if (ret < 0) {
            cts_err("Dump short test data to file failed %d(%s)",
                ret, cts_strerror(ret));
            return ret;
        }
    }

    if (vdata->test_comp_cap) {
        cts_info(" - Save compensate-cap test data to file");
        ret = dump_comp_cap_to_csv_file(
            vdata->comp_cap_data_filepath, vdata->comp_cap_test_data,
            rows, cols);
        if (ret < 0) {
            cts_err("Dump compensate cap test data to file failed %d(%s)",
                ret, cts_strerror(ret));
            return ret;
        }
    }

	if (vdata->rawdata_data_filepath)
		kfree(vdata->rawdata_data_filepath);
	if (vdata->noise_data_filepath)
		kfree(vdata->noise_data_filepath);
	if (vdata->open_data_filepath)
		kfree(vdata->open_data_filepath);
	if (vdata->short_data_filepath)
		kfree(vdata->short_data_filepath);
	if (vdata->comp_cap_data_filepath)
		kfree(vdata->comp_cap_data_filepath);

    return 0;
}

static int init_baseline_test_param(struct cts_vendor_data *vdata)
{
    cts_info("Init baseline test param");

    vdata->test_reset_pin = true;

    vdata->test_int_pin = false;

    vdata->test_rawdata = true;
    vdata->rawdata_test_frames = 1;
    vdata->rawdata_min = 1000;
    vdata->rawdata_max = 3000;

    vdata->test_noise = true;
    vdata->noise_test_frames = 50;
    vdata->noise_max = 50;

    vdata->test_open = true;
    vdata->open_min = 1000;

    vdata->test_short = true;
    vdata->short_min = 400;

    vdata->test_comp_cap = true;
    vdata->comp_cap_min = 1;
    vdata->comp_cap_max = 126;

    return 0;
}

static void do_baseline_test(struct cts_vendor_data *vdata)
{
    struct cts_device *cts_dev = &vdata->cts_data->cts_dev;
    struct cts_test_param reset_pin_test_param = {
        .test_item = CTS_TEST_RESET_PIN,
        .flags = 0,
    };
/*
    struct cts_test_param int_pin_test_param = {
        .test_item = CTS_TEST_INT_PIN,
        .flags = 0,
    };
*/
    struct cts_rawdata_test_priv_param rawdata_test_priv_param = {0};
    struct cts_test_param rawdata_test_param = {
        .test_item = CTS_TEST_RAWDATA,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MIN |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
                 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/rawdata.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
        .priv_param = &rawdata_test_priv_param,
        .priv_param_size = sizeof(rawdata_test_priv_param),
    };
    struct cts_noise_test_priv_param noise_test_priv_param = {0};
    struct cts_test_param noise_test_param = {
        .test_item = CTS_TEST_NOISE,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
                 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
                 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/noise.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
        .priv_param = &noise_test_priv_param,
        .priv_param_size = sizeof(noise_test_priv_param),
    };
    struct cts_test_param open_test_param = {
        .test_item = CTS_TEST_OPEN,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MIN |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
                 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/open.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
    };
    struct cts_test_param short_test_param = {
        .test_item = CTS_TEST_SHORT,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MIN |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
                 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/short.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
    };
    struct cts_test_param comp_cap_test_param = {
        .test_item = CTS_TEST_COMPENSATE_CAP,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MIN |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
                 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/compensate-cap.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
    };

    rawdata_test_priv_param.frames = vdata->rawdata_test_frames;
    rawdata_test_param.min = &vdata->rawdata_min;
    rawdata_test_param.max = &vdata->rawdata_max;
    rawdata_test_param.test_data_buf = vdata->rawdata_test_data;
    rawdata_test_param.test_data_buf_size = vdata->rawdata_test_data_buf_size;
    vdata->rawdata_test_data_size = 0;
    rawdata_test_param.test_data_wr_size = &vdata->rawdata_test_data_size;

    noise_test_priv_param.frames = vdata->noise_test_frames;
    noise_test_param.max = &vdata->noise_max;
    noise_test_param.test_data_buf = vdata->noise_test_data;
    noise_test_param.test_data_buf_size = vdata->noise_test_data_buf_size;
    vdata->noise_test_data_size = 0;
    noise_test_param.test_data_wr_size = &vdata->noise_test_data_size;

    open_test_param.min = &vdata->open_min;
    open_test_param.test_data_buf = vdata->open_test_data;
    open_test_param.test_data_buf_size = vdata->open_test_data_buf_size;
    vdata->open_test_data_size = 0;
    open_test_param.test_data_wr_size = &vdata->open_test_data_size;

    short_test_param.min = &vdata->short_min;
    short_test_param.test_data_buf = vdata->short_test_data;
    short_test_param.test_data_buf_size = vdata->short_test_data_buf_size;
    vdata->short_test_data_size = 0;
    short_test_param.test_data_wr_size = &vdata->short_test_data_size;

    comp_cap_test_param.min = &vdata->comp_cap_min;
    comp_cap_test_param.max = &vdata->comp_cap_max;
    comp_cap_test_param.test_data_buf = vdata->comp_cap_test_data;
    comp_cap_test_param.test_data_buf_size = vdata->comp_cap_test_data_buf_size;
    vdata->short_test_data_size = 0;
    comp_cap_test_param.test_data_wr_size = &vdata->short_test_data_size;

    if (vdata->test_reset_pin) {
        vdata->reset_pin_test_result =
            cts_test_reset_pin(cts_dev, &reset_pin_test_param);
    }
/* MTK PLATFORM NOT NEED TEST INT PIN
    if (vdata->test_int_pin) {
        vdata->int_pin_test_result =
            cts_test_int_pin(cts_dev, &int_pin_test_param);
    } else {
		vdata->int_pin_test_result = 0;
	}
*/
    if (vdata->test_rawdata) {
        vdata->rawdata_test_result =
            cts_test_rawdata(cts_dev, &rawdata_test_param);
    }
    if (vdata->test_noise) {
        vdata->noise_test_result =
            cts_test_noise(cts_dev, &noise_test_param);
    }
    if (vdata->test_open) {
        vdata->open_test_result =
            cts_test_open(cts_dev, &open_test_param);
    }
    if (vdata->test_short) {
        vdata->short_test_result =
            cts_test_short(cts_dev, &short_test_param);
    }
    if (vdata->test_comp_cap) {
        vdata->comp_cap_test_result =
            cts_test_compensate_cap(cts_dev, &comp_cap_test_param);
    }
}

static int cts_do_baseline_test(struct seq_file *s, void *v)
{
	struct touchpanel_data *ts = s->private;
	struct chipone_ts_data *cts_data = NULL;
	struct cts_vendor_data *vdata = NULL;
	//char buf[256];
	//int count = 0;
	int errors = 0;
	int ret;
	
	cts_data = ts->chip_data;
	if (!ts) {
		cts_err("ts null!");
		return 0;
	}
	
	vdata = cts_data->vendor_data;

	ret = init_baseline_test_param(vdata);
    if (ret) {
        cts_err("Init baseline test param failed %d", ret);
        return ret;
    }
	
	ret = alloc_baseline_test_data_mem(vdata,
        cts_data->cts_dev.fwdata.rows * cts_data->cts_dev.fwdata.cols);
    if (ret) {
        cts_err("Alloc baseline test data mem failed");
        return 0;
    }
	
	do_baseline_test(vdata);
 /*	
	ret = save_baseline_test_data_to_file(vdata);
    if (ret) {
        cts_err("Save baseline test data to file failed %d", ret);
    }

	count += scnprintf(buf + count, PAGE_SIZE, "%s %s\n", "  Reset-Pin :",
			vdata->reset_pin_test_result ? "Error" : "Pass");
	count += scnprintf(buf + count, PAGE_SIZE, "%s %s\n", "  Rawdata   :",
			vdata->rawdata_test_result ?   "Error" : "Pass");
	count += scnprintf(buf + count, PAGE_SIZE, "%s %s\n", "  Noise     :",
			vdata->noise_test_result ?     "Error" : "Pass");
	count += scnprintf(buf + count, PAGE_SIZE, "%s %s\n", "  Open      :",
			vdata->open_test_result ?      "Error" : "Pass");
	count += scnprintf(buf + count, PAGE_SIZE, "%s %s\n", "  Short     :",
			vdata->short_test_result ?     "Error" : "Pass");
	count += scnprintf(buf + count, PAGE_SIZE, "%s %s\n", "  Comp-cap  :",
			vdata->comp_cap_test_result ?  "Error" : "Pass");
	seq_printf(s, buf);


	count += scnprintf(buf + count, PAGE_SIZE, "%d", 0);
	seq_printf(s, buf);
*/
	errors = vdata->reset_pin_test_result
			+ vdata->rawdata_test_result
			+ vdata->noise_test_result
			+ vdata->open_test_result
			+ vdata->short_test_result
			+ vdata->comp_cap_test_result;
	seq_printf(s, "%d errors. %s\n", errors, errors ? "" : "All test passed.");
	cts_info("Baseline Test: %d errors. %s", errors, errors ? "" : "All test passed.");
	return 0;
}

static int proc_baseline_test_open(struct inode *i, struct file *f)
{
	return single_open(f, cts_do_baseline_test, PDE_DATA(i));
}

static const struct file_operations proc_baseline_test_fops = {
    .owner   = THIS_MODULE,
    .open    = proc_baseline_test_open,
    .read    = seq_read,
    .release = single_release,
};

int cts_create_proc(struct touchpanel_data *ts)
{
	int ret = 0;
	struct proc_dir_entry *entry = NULL;
	entry = proc_create_data("baseline_test", 0666, ts->prEntry_tp,
			&proc_baseline_test_fops, ts);
	if (entry == NULL) {
		cts_err("Create baseline proc failed");
		ret = -ENOMEM;
	}
	return ret;
}


#endif

int cts_vendor_init(struct chipone_ts_data *cts_data)
{
    struct cts_vendor_data *vdata = NULL;
    int ret;

    if (cts_data == NULL) {
        cts_err("Init with cts_data = NULL");
        return -EINVAL;
    }

    cts_info("Init");

    cts_data->vendor_data = NULL;

    vdata = kzalloc(sizeof(*vdata), GFP_KERNEL);
    if (vdata == NULL) {
        cts_err("Alloc vendor data failed");
        return -ENOMEM;
    }

	cts_create_proc(tsdata);

    cts_data->vendor_data = vdata;
	vdata->cts_data = cts_data;

    return 0;
}

int cts_vendor_deinit(struct chipone_ts_data *cts_data)
{
    struct cts_vendor_data *vdata = NULL;

    if (cts_data == NULL) {
        cts_err("Deinit with cts_data = NULL");
        return -EINVAL;
    }

    if (cts_data->vendor_data == NULL) {
        cts_warn("Deinit with vendor_data = NULL");
        return -EINVAL;
    }

    cts_info("Deinit");

    vdata = cts_data->vendor_data;

    free_baseline_test_data_mem(vdata);
	
    kfree(cts_data->vendor_data);
    cts_data->vendor_data = NULL;

    return 0;
}

