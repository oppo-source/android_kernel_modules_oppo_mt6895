#define LOG_TAG "VENDOR"

#include <linux/firmware.h>

#include "cts_config.h"
#include "cts_platform.h"
#include "cts_core.h"
#include "cts_test.h"
#include "cts_firmware.h"
#include "cts_strerror.h"

#include "../touchpanel_common.h"
#include "../tp_devices.h"
#include "../util_interface/touch_interfaces.h"

#define TPD_DEVICE "chipone,icnl9911c"

#define CALLBACK() cts_err("%s called", __func__)

#define ts2cts(ts)			((struct chipone_ts_data *)(ts->chip_data))
#define cts2ts(cts)			((struct touchpanel_data *)(cts->tsdata))
#define chip2cts(chip)		((struct chipone_ts_data *)(chip_data))

struct chipone_ts_data *chipone_ts_data = NULL;
struct touchpanel_data *tsdata = NULL;

extern int cts_driver_init(void);
extern void cts_driver_exit(void);
extern int cts_suspend(struct chipone_ts_data *cts_data);
extern int cts_resume(struct chipone_ts_data *cts_data);

static int cts_get_chip_info(void *chip_data)
{
    //struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
    //(void)cts_data;
    cts_err("%s", tsdata->panel_data.manufacture_info.version);
    CALLBACK();

    return 0;
}

static int cts_ftm_process(void *chip_data)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	(void)cts_data;

	CALLBACK();
	cts_err("%s:is called !\n", __func__);
	return 0;
}

static int cts_rotative_switch(void *chip_data, int mode)
{
    struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
    struct cts_device *cts_dev = &cts_data->cts_dev;
    int direction;
    int ret = 0;

    direction = cts_data->touch_direction;

    cts_info("direction:%d, mode:%d", direction, mode);

    ret = cts_fw_reg_writeb(cts_dev, CTS_DEVICE_FW_REG_LANDSCAPE_MODE, direction);
    if (ret) {
        cts_err("Set direction: %d, failed!", direction);
    }
    return ret;
}

static int cts_mode_switch(void *chip_data, work_mode mode, bool flag)
{
    struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
    struct cts_device *cts_dev = &cts_data->cts_dev;
    int ret;

    cts_info("%s: mode=%d , flag=%d, enable=%d", __func__, mode, flag, tsdata->gesture_enable);

    switch(mode) {
        case MODE_NORMAL:
            break;
        case MODE_SLEEP:
            ret = cts_send_command(cts_dev, CTS_CMD_SUSPEND);
            if (ret)
                cts_err("Set CTS_CMD_SUSPEND failed %d", ret);
            break;
        case MODE_EDGE:
            ret = cts_rotative_switch(chip_data, flag);
            if (ret)
                cts_err("Set rotative switch failed %d", ret);
            break;
        case MODE_GESTURE:
            if (flag) {
                ret = cts_send_command(cts_dev, CTS_CMD_SUSPEND_WITH_GESTURE);
                if (ret)
                    cts_err("Set CTS_CMD_SUSPEND_WITH_GESTURE failed %d", ret);
            }
            break;
        case MODE_CHARGE:
            cts_info("Set charger mode: %d", flag);
            ret = cts_set_dev_charger_attached(cts_dev, flag);
            if (ret)
                cts_err("Set charger mode failed %d", ret);
            break;
        case MODE_GAME:
            cts_info("Set game mode: %d", flag);
            ret = cts_fw_reg_writeb(cts_dev, 0x086E, flag ? 1 : 0);
            if (ret)
                cts_err("Set dev game mode failed %d", ret);
            break;
        case MODE_HEADSET:
            cts_info("Set earjack mode: %d", flag);
            ret = cts_set_dev_earjack_attached(cts_dev, flag);
            if (ret)
                cts_err("Set earjack mode failed %d", ret);
            break;
        default:
            break;
    }

	return 0;
}

static u8 cts_trigger_reason(void *chip_data, int gesture_enable, int is_suspended)
{
	//struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	//CALLBACK();

	if (gesture_enable && is_suspended) {
		return IRQ_GESTURE;
	} else {
		return IRQ_TOUCH;
	}
}

int cts_get_touchinfo(const struct cts_device *cts_dev,
        struct cts_device_touch_info *touch_info);
static int cts_get_touch_points(void *chip_data, struct point_info *points, int max_num)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	struct cts_device *cts_dev = &cts_data->cts_dev;
	struct cts_device_touch_info *touch_info = &cts_dev->pdata->touch_info;
	struct cts_device_touch_msg *msgs = touch_info->msgs;
	int num = touch_info->num_msg;
	int obj_attention = 0;
	int ret = -1;
	int i;

    if (cts_dev->rtdata.program_mode) {
        cts_err("IRQ triggered in program mode");
        return -EINVAL;
    }

	cts_lock_device(cts_dev);
	ret = cts_get_touchinfo(cts_dev, touch_info);
	cts_unlock_device(cts_dev);
	if (ret < 0) {
		cts_err("Get touch info failed %d", ret);
		return ret;
	}

	cts_dbg("Process touch %d msgs", num);
	if (num == 0 || num > CFG_CTS_MAX_TOUCH_NUM) {
		return 0;
	}

	for (i = 0; i < (num > max_num ? max_num : num); i++) {
		u16 x, y;

		x = le16_to_cpu(msgs[i].x);
		y = le16_to_cpu(msgs[i].y);

#ifdef CFG_CTS_SWAP_XY
		swap(x, y);
#endif
#ifdef CFG_CTS_WRAP_X
		x = wrap(pdata->res_x, x);
#endif
#ifdef CFG_CTS_WRAP_Y
		y = wrap(pdata->res_y, y);
#endif
        cts_dbg("  Process touch msg[%d]: id[%u] ev=%u x=%u y=%u p=%u",
                i, msgs[i].id, msgs[i].event, x, y, msgs[i].pressure);
        if ((msgs[i].id < max_num) &&
                ((msgs[i].event == CTS_DEVICE_TOUCH_EVENT_DOWN) ||
                (msgs[i].event == CTS_DEVICE_TOUCH_EVENT_MOVE) ||
                (msgs[i].event == CTS_DEVICE_TOUCH_EVENT_STAY)))
        {
            points[msgs[i].id].x = x;
            points[msgs[i].id].y = y;
            points[msgs[i].id].z = 1;
            points[msgs[i].id].width_major = 0;
            points[msgs[i].id].touch_major = 0;
            points[msgs[i].id].status = 1;
            //points[msgs[i].id].type = 0;
            obj_attention |= (1 << msgs[i].id);
        }
    }

	return obj_attention;
}

static int cts_wrap_get_gesture_info(void *chip_data, struct gesture_info *gesture)
{
	struct chipone_ts_data *cts_data = chip2cts(chip_data);
	struct cts_device *cts_dev = &cts_data->cts_dev;
	struct cts_device_gesture_info cts_gesture_info;
	int ret = -1;

	if (cts_dev->rtdata.program_mode) {
		cts_err("IRQ triggered in program mode");
		return -EINVAL;
	}

/*
	if (tsdata->is_suspended) {
#ifdef CFG_CTS_GESTURE

		if (cts_dev->rtdata.gesture_wakeup_enabled) {
			cts_info("Get gesture information");
*/
			cts_lock_device(cts_dev);
			ret = cts_get_gesture_info(cts_dev, &cts_gesture_info, CFG_CTS_GESTURE_REPORT_TRACE);
			if (ret) {
				cts_warn("Get gesture info failed %d", ret);
				cts_unlock_device(cts_dev);
				return ret;
			}

			/** - Issure another suspend with gesture wakeup command to device
			 * after get gesture info.
			 */
			cts_info("Set device enter gesture mode");
			cts_send_command(cts_dev, CTS_CMD_SUSPEND_WITH_GESTURE);
			cts_unlock_device(cts_dev);

			cts_info("Process gesture, id=0x%02x, num_points=%d",
					cts_gesture_info.gesture_id, cts_gesture_info.num_points);

			memset(gesture, 0, sizeof(*gesture));
			switch(cts_gesture_info.gesture_id) {
				case CTS_GESTURE_D_TAP:
					gesture->gesture_type = DouTap;
					break;
				case CTS_GESTURE_V:
					gesture->gesture_type = UpVee;
					break;
				case CTS_GESTURE_M:
					gesture->gesture_type = Mgestrue;
					break;
				case CTS_GESTURE_W:
					gesture->gesture_type = Wgestrue;
					break;
				case CTS_GESTURE_O:
					gesture->gesture_type = Circle;
					break;
				case CTS_GESTURE_RV:
					gesture->gesture_type = DownVee;
					break;
				case CTS_GESTURE_UP:
					gesture->gesture_type = Down2UpSwip;
					break;
				case CTS_GESTURE_DOWN:
					gesture->gesture_type = Up2DownSwip;
					break;
				case CTS_GESTURE_LEFT:
					gesture->gesture_type = Right2LeftSwip;
					break;
				case CTS_GESTURE_RIGHT:
					gesture->gesture_type = Left2RightSwip;
					break;
				case CTS_GESTURE_DDOWN:
					gesture->gesture_type = DouSwip;
					break;
				case CTS_GESTURE_LR:
					gesture->gesture_type = RightVee;
					break;
				case CTS_GESTURE_RR:
					gesture->gesture_type = LeftVee;
					break;
				default:
					gesture->gesture_type = UnkownGesture;
					break;
			}

			if (cts_gesture_info.num_points >= 1) {
				gesture->Point_start.x = cts_gesture_info.points[0].x;
				gesture->Point_start.y = cts_gesture_info.points[0].y;
			}
			if (cts_gesture_info.num_points >= 2) {
				gesture->Point_end.x = cts_gesture_info.points[1].x;
				gesture->Point_end.y = cts_gesture_info.points[1].y;
			}
			if (cts_gesture_info.num_points >= 3) {
				gesture->Point_1st.x = cts_gesture_info.points[2].x;
				gesture->Point_1st.y = cts_gesture_info.points[2].y;
			}
			if (cts_gesture_info.num_points >= 4) {
				gesture->Point_2nd.x = cts_gesture_info.points[3].x;
				gesture->Point_2nd.y = cts_gesture_info.points[3].y;
			}
			if (cts_gesture_info.num_points >= 5) {
				gesture->Point_3rd.x = cts_gesture_info.points[4].x;
				gesture->Point_3rd.y = cts_gesture_info.points[4].y;
			}
			if (cts_gesture_info.num_points >= 6) {
				gesture->Point_4th.x = cts_gesture_info.points[5].x;
				gesture->Point_4th.y = cts_gesture_info.points[5].y;
			}
			return 0;
/*		} else {
			cts_warn("IRQ triggered while device suspended "
					"without gesture wakeup enable");
			return -EINVAL;
		}

#endif  CFG_CTS_GESTURE 
	} else {
		cts_err("Get gesture info while not suspended");
		return -EINVAL;
	}

	return 0;
*/
}

static int cts_read_fw_ddi_version(void *chip_data, struct touchpanel_data *ts)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	struct cts_device *cts_dev = &cts_data->cts_dev;
	u16 fw_ver;
	u8 ddi_ver;
	char *version;
	int ret = -1;

	version = ts->panel_data.manufacture_info.version;
	if (version) {
		ret = cts_get_ddi_version(cts_dev, &ddi_ver);
		if (ret)
			cts_err("get ddi version failed");
		
		ret = cts_get_firmware_version(cts_dev, &fw_ver);
		if (ret)
			cts_err("get firmware version failed");
		
		scnprintf(version, 16, "TXD_9911C_%X%02X", ddi_ver, fw_ver);
		cts_info("%s", version);
    }
	
	return ret;
}

fw_update_state cts_fw_update(void *chip_data, const struct firmware *fw, bool force)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	struct cts_device *cts_dev = &cts_data->cts_dev;
	struct cts_firmware cts_firmware;
	int ret;

	cts_firmware.name = "ICNL9911.bin";
	cts_firmware.hwid = CTS_DEV_HWID_ICNL9911C;
	cts_firmware.fwid = CTS_DEV_FWID_ICNL9911C;
	cts_firmware.data = (u8 *)fw->data;
	cts_firmware.size = fw->size;
	cts_firmware.fw = (struct firmware *)fw;

	cts_lock_device(cts_dev);
	ret = cts_update_firmware(cts_dev, &cts_firmware, false);
	cts_unlock_device(cts_dev);
	if (ret < 0) {
		return FW_UPDATE_ERROR;
	}

	if (cts_enter_normal_mode(cts_dev) < 0) {
		return FW_UPDATE_ERROR;
	}

	cts_lock_device(cts_dev);
	ret = cts_read_fw_ddi_version(chip_data, tsdata);
	cts_unlock_device(cts_dev);
	if (ret)
		cts_err("get fw_ddi_version failed");
	
	return FW_UPDATE_SUCCESS;
}


static int cts_get_vendor(void *chip_data, struct panel_info  *panel_data)
{
	//CALLBACK();
	return 0;
}

static int cts_reset(void *chip_data)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	const struct firmware *fw = NULL;
	int ret;

	cts_plat_reset_device(cts_data->pdata);

		ret = request_firmware(&fw, tsdata->panel_data.fw_name, tsdata->dev);
		cts_info("request_firmware %s", tsdata->panel_data.fw_name);
		if (ret) {
			cts_err("request_firmware failed!");
			return -1;
		}
	
	ret = cts_fw_update(chip_data, fw, false);
	if (ret == FW_UPDATE_SUCCESS) {
		cts_info("fw_update success!");
	} else if (ret == FW_UPDATE_ERROR) {
		cts_err("fw_update failed!");
	}
	release_firmware(fw);
	return 0;
}

static void cts_tp_touch_release(struct touchpanel_data *ts)
{
#ifdef TYPE_B_PROTOCOL

    int i = 0;

    if (ts->report_flow_unlock_support) {
        mutex_lock(&ts->report_mutex);
    }
    for (i = 0; i < ts->max_num; i++) {
        input_mt_slot(ts->input_dev, i);
        input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, 0);
    }
    input_report_key(ts->input_dev, BTN_TOUCH, 0);
    input_report_key(ts->input_dev, BTN_TOOL_FINGER, 0);
    input_sync(ts->input_dev);
    if (ts->report_flow_unlock_support) {
        mutex_unlock(&ts->report_mutex);
    }
#else
    input_report_key(ts->input_dev, BTN_TOUCH, 0);
    input_report_key(ts->input_dev, BTN_TOOL_FINGER, 0);
    input_mt_sync(ts->input_dev);
    input_sync(ts->input_dev);
#endif
    cts_info("release all touch point");
    ts->view_area_touched = 0; //realse all touch point,must clear this flag
    ts->touch_count = 0;
    ts->irq_slot = 0;
}

static int cts_esd_handle(void* chip_data)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	struct cts_device *cts_dev = &cts_data->cts_dev;
    int retry = 5;
    int ret;

    cts_dbg("ESD protection work");

    cts_lock_device(cts_dev);
	ret = cts_plat_is_normal_mode(cts_data->pdata);//0:means esd hanppened
	cts_unlock_device(cts_dev);
    if (!ret) {
		cts_err("Handle ESD event!");
		do {
			if (cts_reset(chip_data))
				cts_err("Reset chip and update fw failed!");
			else
				break;
		} while (retry--);
		ret = -1;
		cts_tp_touch_release(tsdata);
    } else {
		ret = 0;
        cts_dbg("None ESD event!");
    }
	
	return ret;
}

static fw_check_state cts_fw_check(void *chip_data, struct resolution_info *resolution_info,
		struct panel_info *panel_data)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	struct cts_device *cts_dev = &cts_data->cts_dev;
	u16 fwid;

	CALLBACK();

	if (cts_get_fwid(cts_dev, &fwid) < 0) {
		return FW_ABNORMAL;
	}
	if (fwid == CTS_DEV_FWID_INVALID) {
		return FW_ABNORMAL;
	}

	return FW_NORMAL;
}

static int cts_power_control(void *chip_data, bool enable)
{
	CALLBACK();
	return 0;
}

static bool set_gesture_raw_type(struct cts_device *cts_dev, u8 type)
{
    u8 val = 0xff, r;

    r = cts_fw_reg_writeb(cts_dev, 0x45, type);
    if (r) {
        cts_err("Set gesture raw type failed %d(%s)", r, cts_strerror(r));
        return false;
    }

    r = cts_fw_reg_readb(cts_dev, 0x45, &val);
    if (r) {
        cts_err("Get gesture raw type failed %d(%s)", r, cts_strerror(r));
        return false;
    }
    return val == type;
}

extern void cts_dump_tsdata(struct cts_device *cts_dev,
        const char *desc, const u16 *data, bool to_console);
extern int validate_tsdata(struct cts_device *cts_dev,
    const char *desc, u16 *data,
    u32 *invalid_nodes, u32 num_invalid_nodes,
    bool per_node, int *min, int *max);
int cts_test_gesture_rawdata(struct cts_device *cts_dev,
        struct cts_test_param *param)
{
    struct cts_rawdata_test_priv_param *priv_param;
    bool driver_validate_data = false;
    bool validate_data_per_node = false;
    bool stop_test_if_validate_fail = false;
    bool dump_test_data_to_user = false;
    bool dump_test_data_to_console = false;
    bool dump_test_data_to_file = false;
    int  num_nodes;
    int  tsdata_frame_size;
    int  frame;
    int  idle_mode;
    u16 *gesture_rawdata = NULL;
    int  i;
    int  ret;

    if ((!cts_dev) || (!param) || param->priv_param_size != sizeof(*priv_param) || (!(param->priv_param))) {
        cts_err("Gesture rawdata test with invalid cts_dev or param priv param is null");
        return -EINVAL;
    }

    priv_param = param->priv_param;
    if (priv_param->frames <= 0) {
        cts_info("Gesture rawdata test with too little frame %u",
            priv_param->frames);
        return -EINVAL;
    }

    num_nodes = cts_dev->fwdata.rows * cts_dev->fwdata.cols;
    tsdata_frame_size = 2 * num_nodes;

    driver_validate_data =
        !!(param->flags & CTS_TEST_FLAG_VALIDATE_DATA);
    validate_data_per_node =
        !!(param->flags & CTS_TEST_FLAG_VALIDATE_PER_NODE);
    dump_test_data_to_user =
        !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE);
    dump_test_data_to_console =
        !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE);
    dump_test_data_to_file =
        !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE);
    stop_test_if_validate_fail =
        !!(param->flags & CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED);

    cts_info("Gesture rawdata test, flags: 0x%08x, frames: %d, "
               "num invalid node: %u, "
               "test data file: '%s' buf size: %d, "
               "drive log file: '%s' buf size: %d",
        param->flags, priv_param->frames, param->num_invalid_node,
        param->test_data_filepath, param->test_data_buf_size,
        param->driver_log_filepath, param->driver_log_buf_size);


    if (dump_test_data_to_user) {
        gesture_rawdata = (u16 *)param->test_data_buf;
    } else {
        gesture_rawdata = (u16 *)kmalloc(tsdata_frame_size, GFP_KERNEL);
        if (gesture_rawdata == NULL) {
            cts_err("Allocate memory for rawdata failed");
            return -ENOMEM;
        }
    }

    /* Stop device to avoid un-wanted interrrupt */
    ret = cts_stop_device(cts_dev);
    if (ret) {
        cts_err("Stop device failed %d(%s)", ret, cts_strerror(ret));
        goto free_mem;
    }

    cts_lock_device(cts_dev);

    idle_mode = priv_param->work_mode;

    for (i = 0; i < 5; i++) {
        int r;
        u8 val;

        r = cts_enable_get_rawdata(cts_dev);
        if (r) {
            cts_err("Enable get tsdata failed %d(%s)",
                r, cts_strerror(r));
            continue;
        }
        mdelay(1);
        r = cts_fw_reg_readb(cts_dev, 0x12, &val);
        if (r) {
            cts_err("Read enable get tsdata failed %d(%s)",
                r, cts_strerror(r));
            continue;
        }
        if (val != 0) {
            break;
        }
    }

    if (i >= 5) {
        cts_err("Enable read tsdata failed");
        ret = -EIO;
        goto unlock_device;
    }

    if (dump_test_data_to_file) {
        int r = cts_start_dump_test_data_to_file(param->test_data_filepath,
            !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE_APPEND));
        if (r) {
            cts_err("Start dump test data to file failed %d(%s)",
                r, cts_strerror(r));
        }
    }

    for (frame = 0; frame < priv_param->frames; frame++) {
        bool data_valid = false;
        int  r;

        r = cts_set_work_mode(cts_dev, CTS_WORK_MODE_GESTURE_ACTIVE);
        if (r) {
            cts_err("Set work mode:%d failed %d(%s)",
                CTS_WORK_MODE_GESTURE_ACTIVE, r, cts_strerror(r));
            continue;
        }

        r = cts_send_command(cts_dev, CTS_CMD_QUIT_GESTURE_MONITOR);
        if (r) {
            cts_err("Send CMD_QUIT_GESTURE_MONITOR failed %d(%s)",
                r, cts_strerror(r));
        }

        if (!set_gesture_raw_type(cts_dev, idle_mode)) {
           cts_err("Set gesture raw type failed");
           continue;
        }

        for (i = 0; i < 3; i++) {
            r = cts_get_rawdata(cts_dev, gesture_rawdata);
            if (r) {
                cts_err("Get gesture rawdata failed %d(%s)",
                    r, cts_strerror(r));
                mdelay(30);
            } else {
                data_valid = true;
                break;
            }
        }

        if (!data_valid) {
            ret = -EIO;
            break;
        }

        if (dump_test_data_to_user) {
			*param->test_data_wr_size = 0;
            *param->test_data_wr_size += tsdata_frame_size;
        }

        if (dump_test_data_to_console || dump_test_data_to_file) {
            cts_dump_tsdata(cts_dev,
                idle_mode ? "Gesture Rawdata" : "Gesture LP Rawdata",
                gesture_rawdata, dump_test_data_to_console);
        }

        if (driver_validate_data) {
            ret = validate_tsdata(cts_dev,
                idle_mode ? "Gesture Rawdata" : "Gesture LP Rawdata",
                gesture_rawdata, param->invalid_nodes, param->num_invalid_node,
                validate_data_per_node, param->min, param->max);
            if (ret) {
                cts_err("Gesture Rawdata test failed %d(%s)",
                    ret, cts_strerror(ret));
                if (stop_test_if_validate_fail) {
                    break;
                }
            }
        }

        if (dump_test_data_to_user) {
            gesture_rawdata += num_nodes;
        }
    }

    if (dump_test_data_to_file) {
        cts_stop_dump_test_data_to_file();
    }

    for (i = 0; i < 5; i++) {
        int r = cts_disable_get_rawdata(cts_dev);
        if (r) {
            cts_err("Disable get rawdata failed %d(%s)",
                r, cts_strerror(r));
            continue;
        } else {
            break;
        }
    }

unlock_device:
    cts_unlock_device(cts_dev);

    {
        int r = cts_start_device(cts_dev);
        if (r) {
            cts_err("Start device failed %d(%s)", r, cts_strerror(r));
        }
    }

free_mem:
    if (!dump_test_data_to_user && gesture_rawdata != NULL) {
        kfree(gesture_rawdata);
    }

    return ret;
}

int cts_test_gesture_noise(struct cts_device *cts_dev,
        struct cts_test_param *param)
{
    struct cts_noise_test_priv_param *priv_param;
    bool driver_validate_data = false;
    bool validate_data_per_node = false;
    bool dump_test_data_to_user = false;
    bool dump_test_data_to_console = false;
    bool dump_test_data_to_file = false;
    int  num_nodes;
    int  tsdata_frame_size;
    int  frame;
    int  idle_mode;
    u16 *buffer = NULL;
    int  buf_size = 0;
    u16 *curr_rawdata = NULL;
    u16 *max_rawdata = NULL;
    u16 *min_rawdata = NULL;
    u16 *gesture_noise = NULL;
    bool first_frame = true;
    int  i;
    int  ret;

    if ((!cts_dev) || (!param) || param->priv_param_size != sizeof(*priv_param) || (!(param->priv_param))) {
        cts_err("Noise test with invalid param: cts_dev or param or priv param is null");
        return -EINVAL;
    }

    priv_param = param->priv_param;
    if (priv_param->frames < 2) {
        cts_err("Noise test with too little frame %u",
            priv_param->frames);
        return -EINVAL;
    }

    num_nodes = cts_dev->fwdata.rows * cts_dev->fwdata.cols;
    tsdata_frame_size = 2 * num_nodes;

    driver_validate_data =
        !!(param->flags & CTS_TEST_FLAG_VALIDATE_DATA);
    validate_data_per_node =
        !!(param->flags & CTS_TEST_FLAG_VALIDATE_PER_NODE);
    dump_test_data_to_user =
        !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE);
    dump_test_data_to_console =
        !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE);
    dump_test_data_to_file =
        !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE);

    cts_info("Noise test, flags: 0x%08x, frames: %d, "
               "num invalid node: %u, "
               "test data file: '%s' buf size: %d, "
               "drive log file: '%s' buf size: %d",
        param->flags, priv_param->frames, param->num_invalid_node,
        param->test_data_filepath, param->test_data_buf_size,
        param->driver_log_filepath, param->driver_log_buf_size);


    buf_size = (driver_validate_data ? 4 : 1) * tsdata_frame_size;
    buffer = (u16 *)kmalloc(buf_size, GFP_KERNEL);
    if (buffer == NULL) {
        cts_err("Alloc mem for touch data failed");
        return -ENOMEM;
    }

    curr_rawdata = buffer;
    if (driver_validate_data) {
        max_rawdata = curr_rawdata + 1 * num_nodes;
        min_rawdata = curr_rawdata + 2 * num_nodes;
        gesture_noise = curr_rawdata + 3 * num_nodes;
    }

    /* Stop device to avoid un-wanted interrrupt */
    ret = cts_stop_device(cts_dev);
    if (ret) {
        cts_err("Stop device failed %d(%s)", ret, cts_strerror(ret));
        goto free_mem;
    }

    cts_lock_device(cts_dev);

    idle_mode = priv_param->work_mode;

    for (i = 0; i < 5; i++) {
        int r;
        u8 val;

        r = cts_enable_get_rawdata(cts_dev);
        if (r) {
            cts_err("Enable get ts data failed %d(%s)",
                r, cts_strerror(r));
            continue;
        }
        mdelay(1);
        r = cts_fw_reg_readb(cts_dev, 0x12, &val);
        if (r) {
            cts_err("Read enable get ts data failed %d(%s)",
                r, cts_strerror(r));
            continue;
        }
        if (val != 0) {
            break;
        }
    }

    if (i >= 5) {
        cts_err("Enable read tsdata failed");
        ret = -EIO;
        goto unlock_device;
    }

    if (dump_test_data_to_file) {
        int r = cts_start_dump_test_data_to_file(param->test_data_filepath,
            !!(param->flags & CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE_APPEND));
        if (r) {
            cts_err("Start dump test data to file failed %d(%s)",
                r, cts_strerror(r));
        }
    }

    msleep(50);

    for (frame = 0; frame < priv_param->frames; frame++) {
        int r;

        r = cts_set_work_mode(cts_dev, CTS_WORK_MODE_GESTURE_ACTIVE);
        if (r) {
            cts_err("Set work mode:%d failed %d(%s)",
                CTS_WORK_MODE_GESTURE_ACTIVE, r, cts_strerror(r));
            continue;
        }

        r = cts_send_command(cts_dev, CTS_CMD_QUIT_GESTURE_MONITOR);
        if (r) {
            cts_err("send quit gesture monitor failed %d(%s)",
                r, cts_strerror(r));
            // Ignore this error
        }

        if (!set_gesture_raw_type(cts_dev, idle_mode)) {
           cts_err("Set gesture raw type failed");
           continue;
        }

        for (i = 0; i < 3; i++) {
            r = cts_get_rawdata(cts_dev, curr_rawdata);
            if (r) {
                cts_err("Get rawdata failed %d(%s)",
                    r, cts_strerror(r));
                mdelay(30);
            } else {
                break;
            }
        }

        if (i >= 3) {
            cts_err("Read rawdata failed");
            ret = -EIO;
            goto disable_get_tsdata;
        }

        if (dump_test_data_to_console || dump_test_data_to_file) {
            cts_dump_tsdata(cts_dev,
                idle_mode ? "Gstr Noise-Raw" : "Gstr LP Noise-Raw",
                curr_rawdata, dump_test_data_to_console);
        }

        if (dump_test_data_to_user) {
			*param->test_data_wr_size = 0;
            memcpy(param->test_data_buf + *param->test_data_wr_size,
                curr_rawdata, tsdata_frame_size);
            *param->test_data_wr_size += tsdata_frame_size;
        }

        if (driver_validate_data) {
            if (unlikely(first_frame)) {
                memcpy(max_rawdata, curr_rawdata, tsdata_frame_size);
                memcpy(min_rawdata, curr_rawdata, tsdata_frame_size);
                first_frame = false;
            } else {
                for (i = 0; i < num_nodes; i++) {
                    if (curr_rawdata[i] > max_rawdata[i]) {
                        max_rawdata[i] = curr_rawdata[i];
                    } else if (curr_rawdata[i] < min_rawdata[i]) {
                        min_rawdata[i] = curr_rawdata[i];
                    }
                }
            }
        }
    }

    if (driver_validate_data) {
        for (i = 0; i < num_nodes; i++) {
            gesture_noise[i] = max_rawdata[i] - min_rawdata[i];
        }

        if (dump_test_data_to_user &&
            param->test_data_buf_size >=
                (*param->test_data_wr_size + tsdata_frame_size)) {
            memcpy(param->test_data_buf + *param->test_data_wr_size,
               gesture_noise, tsdata_frame_size);
            *param->test_data_wr_size += tsdata_frame_size;
       }

        if (dump_test_data_to_console || dump_test_data_to_file) {
            cts_dump_tsdata(cts_dev,
                idle_mode ? "Gesture Noise" : "Gesture LP Noise",
                gesture_noise, dump_test_data_to_console);
        }

        ret = validate_tsdata(cts_dev,
            idle_mode ? "Gesture Noise" : "Gesture LP Noise",
            gesture_noise, param->invalid_nodes, param->num_invalid_node,
            validate_data_per_node, param->min, param->max);
    }

    if (dump_test_data_to_file) {
        cts_stop_dump_test_data_to_file();
    }

disable_get_tsdata:
    for (i = 0; i < 5; i++) {
        int r = cts_disable_get_rawdata(cts_dev);
        if (r) {
            cts_err("Disable get rawdata failed %d(%s)",
                r, cts_strerror(r));
            continue;
        } else {
            break;
        }
    }

unlock_device:
    cts_unlock_device(cts_dev);
    {
        int r = cts_start_device(cts_dev);
        if (r) {
            cts_err("Start device failed %d(%s)",
                r, cts_strerror(r));
        }
    }

free_mem:
    if (buffer) {
        kfree(buffer);
    }

    return ret;
}

static int prepare_black_test(struct cts_device *cts_dev)
{
    int ret;
	u8 buf;

    cts_info("Prepare black test");

    cts_plat_reset_device(cts_dev->pdata);

    ret = cts_set_dev_esd_protection(cts_dev, false);
    if (ret) {
        cts_err("Disable firmware ESD protection failed %d(%s)",
            ret, cts_strerror(ret));
        return ret;
    }

    ret = disable_fw_monitor_mode(cts_dev);
    if (ret) {
        cts_err("Disable firmware monitor mode failed %d(%s)",
            ret, cts_strerror(ret));
        return ret;
    }

	/*Disable GSTR ONLY FS Switch*/
	ret = cts_fw_reg_readb(cts_dev, CTS_DEVICE_FW_REG_GSTR_ONLY_FS_EN, &buf);
	if (ret) {
		cts_err("Get GSTR ONLY FS EN failed %d(%s)", ret, cts_strerror(ret));
		return ret;
	}
	ret = cts_fw_reg_writeb(cts_dev, CTS_DEVICE_FW_REG_GSTR_ONLY_FS_EN, (buf & 0xFB));
	if (ret) {
        cts_err("Disable GSTR ONLY FS failed %d(%s)", ret, cts_strerror(ret));
		return ret;
	}

	/*Enable GSTR DATA DBG*/
	ret = cts_fw_reg_readb(cts_dev, CTS_DEVICE_FW_REG_GSTR_DATA_DBG_EN, &buf);
	if (ret) {
		cts_err("get GSTR DATA DBG EN failed %d(%s)", ret, cts_strerror(ret));
		return ret;
	}

	ret = cts_fw_reg_writeb(cts_dev, CTS_DEVICE_FW_REG_GSTR_DATA_DBG_EN, (buf | BIT(6)));
	if (ret) {
        cts_err("Enable GSTR DATA DBG failed %d(%s)", ret, cts_strerror(ret));
		return ret;
	}

	ret = set_fw_work_mode(cts_dev, CTS_FIRMWARE_WORK_MODE_GSTR_DBG);
	if (ret) {
		cts_err("Set firmware work mode to WORK_MODE_GSTR_DBG failed %d(%s)", ret, cts_strerror(ret));
		return ret;
	}
	ret = cts_fw_reg_readb(cts_dev, CTS_DEVICE_FW_REG_POWER_MODE, &buf);
	if (ret) {
		cts_err("get POWER MODE failed %d(%s)", ret, cts_strerror(ret));
		return ret;
	}

    return 0;
}

static void cts_black_screen_test(void *chip_data, char *msg)
{
    struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
    struct cts_device *cts_dev = &cts_data->cts_dev;
    struct cts_rawdata_test_priv_param gesture_rawdata_test_priv_param = {
        .frames = 3,
        .work_mode = 1,
    };
    struct cts_test_param gesture_rawdata_test_param = {
        .test_item = CTS_TEST_GESTURE_RAWDATA,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MIN |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
                 //CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE,
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/gesture-rawdata.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
        .priv_param = &gesture_rawdata_test_priv_param,
        .priv_param_size = sizeof(gesture_rawdata_test_priv_param),
    };
    struct cts_rawdata_test_priv_param gesture_lp_rawdata_test_priv_param = {
        .frames = 3,
        .work_mode = 0,
    };
    struct cts_test_param gesture_lp_rawdata_test_param = {
        .test_item = CTS_TEST_GESTURE_LP_RAWDATA,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MIN |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
                 //CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE,
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/gesture-lp-rawdata.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
        .priv_param = &gesture_lp_rawdata_test_priv_param,
        .priv_param_size = sizeof(gesture_lp_rawdata_test_priv_param),
    };
    struct cts_noise_test_priv_param gesture_noise_test_priv_param = {
        .frames = 3,
        .work_mode = 1,
    };
    struct cts_test_param gesture_noise_test_param = {
        .test_item = CTS_TEST_GESTURE_NOISE,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
                 //CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE,
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/gesture-noise.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
        .priv_param = &gesture_noise_test_priv_param,
        .priv_param_size = sizeof(gesture_noise_test_priv_param),
    };
    struct cts_noise_test_priv_param gesture_lp_noise_test_priv_param = {
        .frames = 3,
        .work_mode = 0,
    };
    struct cts_test_param gesture_lp_noise_test_param = {
        .test_item = CTS_TEST_GESTURE_LP_NOISE,
        .flags = CTS_TEST_FLAG_VALIDATE_DATA |
                 CTS_TEST_FLAG_VALIDATE_MAX |
                 CTS_TEST_FLAG_STOP_TEST_IF_VALIDATE_FAILED |
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_CONSOLE |
                 //CTS_TEST_FLAG_DUMP_TEST_DATA_TO_USERSPACE,
				 CTS_TEST_FLAG_DUMP_TEST_DATA_TO_FILE,
        .test_data_filepath = "/sdcard/chipone-tddi/test/gesture-lp-noise.csv",
        .num_invalid_node = 0,
        .invalid_nodes = NULL,
        .priv_param = &gesture_lp_noise_test_priv_param,
        .priv_param_size = sizeof(gesture_lp_noise_test_priv_param),
    };

    int gesture_rawdata_min = 0;
    int gesture_rawdata_max = 4000;
    int gesture_lp_rawdata_min = 0;
    int noise_max = 3000;
	
    int gesture_rawdata_test_result = 0;
    int gesture_lp_rawdata_test_result = 0;
    int gesture_noise_test_result = 0;
    int gesture_lp_noise_test_result = 0;
    //int count = 0;
    int errors = 0;

    gesture_rawdata_test_param.min = &gesture_rawdata_min;
    gesture_rawdata_test_param.max = &gesture_rawdata_max;
    gesture_lp_rawdata_test_param.min = &gesture_lp_rawdata_min;
    gesture_lp_rawdata_test_param.max = &gesture_rawdata_max;
    gesture_noise_test_param.max = &noise_max;
    gesture_lp_noise_test_param.max = &noise_max;

	prepare_black_test(cts_dev);

    gesture_rawdata_test_result =
        cts_test_gesture_rawdata(cts_dev, &gesture_rawdata_test_param);
    gesture_lp_rawdata_test_result =
        cts_test_gesture_rawdata(cts_dev, &gesture_lp_rawdata_test_param);
    gesture_noise_test_result =
        cts_test_gesture_noise(cts_dev, &gesture_noise_test_param);
    gesture_lp_noise_test_result =
        cts_test_gesture_noise(cts_dev, &gesture_lp_noise_test_param);

    cts_plat_reset_device(cts_dev->pdata);

/*
	count += scnprintf(msg + count, PAGE_SIZE, "%s %s\n", "  Gesture-raw      :",
			gesture_rawdata_test_result ? "Error" : "Pass");
	count += scnprintf(msg + count, PAGE_SIZE, "%s %s\n", "  Gesture-lp-raw   :",
			gesture_lp_rawdata_test_result ? "Error" : "Pass");
	count += scnprintf(msg + count, PAGE_SIZE, "%s %s\n", "  Gesture-noise    :",
			gesture_noise_test_result ? "Error" : "Pass");
	count += scnprintf(msg + count, PAGE_SIZE, "%s %s\n", "  Gesture-lp-noise :",
			gesture_lp_noise_test_result ? "Error" : "Pass");

	count += scnprintf(msg + count, PAGE_SIZE, "%d", errors);
*/	
	errors = gesture_rawdata_test_result
			+ gesture_lp_rawdata_test_result
			+ gesture_noise_test_result
			+ gesture_lp_noise_test_result;
	sprintf(msg, "%d errors. %s\n", errors, errors ? "" : "All test passed.");
	cts_info("Black Test: %s", msg);
}

static uint8_t cts_get_touch_direction(void *chip_data)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	return cts_data->touch_direction;
}
static void cts_set_touch_direction(void *chip_data, uint8_t dir)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	cts_data->touch_direction = dir;
	cts_info("Set touch_direction:%d", dir);
}

static struct oplus_touchpanel_operations cts_tp_ops = {
	.get_chip_info						= cts_get_chip_info,
	.mode_switch						= cts_mode_switch,
	.get_touch_points					= cts_get_touch_points,
	.get_gesture_info					= cts_wrap_get_gesture_info,
	.ftm_process						= cts_ftm_process,
	.get_vendor							= cts_get_vendor,
	.reset								= cts_reset,
	.reinit_device						= NULL,
	.fw_check							= cts_fw_check,
	.fw_update							= cts_fw_update,
	.power_control						= cts_power_control,
	.reset_gpio_control					= NULL,
	.trigger_reason						= cts_trigger_reason,
	.get_keycode						= NULL,
	.esd_handle							= cts_esd_handle,
	.fw_handle							= NULL,
	.resume_prepare						= NULL,
	.spurious_fp_check					= NULL,
	.finger_proctect_data_get			= NULL,
	.exit_esd_mode						= NULL,
	.register_info_read					= NULL,
	.write_ps_status					= NULL,
	.specific_resume_operate			= NULL,
	.get_usb_state						= NULL,
	.black_screen_test					= cts_black_screen_test,
	.irq_handle_unlock					= NULL,
	.async_work							= NULL,
	.get_face_state						= NULL,
	.health_report						= NULL,
	.bootup_test						= NULL,
	.get_gesture_coord					= NULL,
	.set_touch_direction				= cts_set_touch_direction,
	.get_touch_direction				= cts_get_touch_direction,
};

int cts_fw_update_in_probe(void *chip_data, struct panel_info  *panel_data, bool need_lock)
{
	struct chipone_ts_data *cts_data = (struct chipone_ts_data *)chip_data;
	struct cts_device *cts_dev = &cts_data->cts_dev;
	struct cts_firmware cts_firmware;
	struct firmware fw;
	int ret;

	CALLBACK();

	cts_firmware.name = panel_data->fw_name;
	cts_firmware.hwid = CTS_DEV_HWID_ICNL9911C;
	cts_firmware.fwid = CTS_DEV_FWID_ICNL9911C;
	cts_firmware.data = (u8 *)panel_data->firmware_headfile.firmware_data;
	cts_firmware.size = panel_data->firmware_headfile.firmware_size;
	cts_firmware.fw = &fw;

	if (need_lock) {
		cts_lock_device(cts_dev);
	}
	ret = cts_update_firmware(cts_dev, &cts_firmware, false);
	if (need_lock) {
		cts_unlock_device(cts_dev);
	}

	if (ret < 0) {
		return -1;
	}
	
	cts_read_fw_ddi_version(chip_data, tsdata);
	
	if (cts_enter_normal_mode(cts_dev) < 0) {
		return -1;
	}
	return 0;
}

int cts_register_vendor_dirver(struct chipone_ts_data *cts_data)
{
	int ret;

	if (cts_data == NULL) {
		cts_err("Init with cts_data = NULL");
		return -EINVAL;
	}

	tsdata = common_touch_data_alloc();
	if (tsdata == NULL) {
		cts_err("ts kzalloc error\n");
		return -ENOMEM;
	}
	memset(tsdata, 0, sizeof(*tsdata));

	tsdata->s_client = cts_data->spi_client;
	tsdata->irq = cts_data->pdata->irq;
	tsdata->dev = &cts_data->spi_client->dev;
	tsdata->chip_data = cts_data;
	cts_data->tsdata = tsdata;
	tsdata->ts_ops = &cts_tp_ops;
	tsdata->earsense_ops = NULL;
	tsdata->has_callback = NULL;

	ret = register_common_touch_device(tsdata);
	if (ret < 0) {
		cts_err("register touch device failed: ret=%d", ret);
		goto err_register_driver;
	}

	return 0;

err_register_driver:
	common_touch_data_free(tsdata);
	tsdata = NULL;
	return -ENODEV;
}

static int __init cts_vendor_driver_init(void)
{
    int ret;

    cts_info("Chipone TDDI driver %s", CFG_CTS_DRIVER_VERSION);
	
	if (!tp_judge_ic_match(TPD_DEVICE)) {
		cts_info("%s mismatched", TPD_DEVICE);
		return -ENODEV;
	}

	cts_info("%s matched", TPD_DEVICE);

	ret = cts_driver_init();
	if (ret < 0) {
		cts_err("Init driver failed");
		return ret;
	}

	if (tsdata == NULL) {
		return 0;
	}
	else {
		if (tsdata->fw_update_in_probe_with_headfile) {
			ret = cts_fw_update_in_probe(tsdata->chip_data, &tsdata->panel_data, true);
			if (ret < 0) {
				cts_err("update firmware in probe failed");
				goto error_fw_update;
			}
		}
	}

	return 0;

error_fw_update:
	cts_driver_exit();

    return -ENODEV;
}

static void __exit cts_vendor_driver_exit(void)
{
    cts_info("Chipone TDDI driver exit");
}

module_init(cts_vendor_driver_init);
module_exit(cts_vendor_driver_exit);

MODULE_DESCRIPTION("Chipone TDDI Driver for MTK platform");
MODULE_VERSION(CFG_CTS_DRIVER_VERSION);
MODULE_AUTHOR("Miao Defang <dfmiao@chiponeic.com>");
MODULE_LICENSE("GPL");

