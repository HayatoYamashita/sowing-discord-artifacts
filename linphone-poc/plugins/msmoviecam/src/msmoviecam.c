/*
 * msmoviecam — mediastreamer2 webcam plugin that exposes an mp4/mov file
 * as a synthetic capture device, by piping raw YUV420p frames from a
 * spawned ffmpeg process. Loops indefinitely.
 *
 * Configuration (read from env at filter preprocess time):
 *   MSMOVIECAM_VIDEO   path to the .mp4 / .mov / any-ffmpeg-readable file
 *   MSMOVIECAM_W       output width  (default 640)
 *   MSMOVIECAM_H       output height (default 480)
 *   MSMOVIECAM_FPS     output fps    (default 30)
 *   MSMOVIECAM_FFMPEG  ffmpeg binary path (default "ffmpeg" on PATH)
 *
 * Plugin entry: libmsmoviecam_init() — discovered by ms_factory_load_plugins
 * via the libms*.dylib naming convention on macOS.
 */

#include <bctoolbox/defs.h>
#include "mediastreamer2/mscommon.h"
#include "mediastreamer2/msfactory.h"
#include "mediastreamer2/msfilter.h"
#include "mediastreamer2/msticker.h"
#include "mediastreamer2/msvideo.h"
#include "mediastreamer2/mswebcam.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MSMOVIECAM_DEFAULT_W   640
#define MSMOVIECAM_DEFAULT_H   480
#define MSMOVIECAM_DEFAULT_FPS 30.0f

typedef struct _MovieCamData {
	MSVideoSize vsize;
	float fps;
	int frame_index;
	uint64_t starttime;
	mblk_t *pic;
	MSPicture pict;

	char video_path[1024];
	char ffmpeg_bin[256];

	FILE *ffmpeg_pipe;

	pthread_t reader_thread;
	pthread_mutex_t lock;
	int running;

	uint8_t *current_frame;
	size_t frame_size_bytes;
	int frame_ready;
} MovieCamData;

static size_t read_exact(FILE *f, uint8_t *buf, size_t n) {
	size_t got = 0;
	while (got < n) {
		size_t r = fread(buf + got, 1, n - got, f);
		if (r == 0) {
			if (feof(f) || ferror(f)) return got;
			continue;
		}
		got += r;
	}
	return got;
}

static void *moviecam_reader_thread(void *arg) {
	MovieCamData *d = (MovieCamData *)arg;
	uint8_t *scratch = (uint8_t *)ms_malloc(d->frame_size_bytes);
	while (__atomic_load_n(&d->running, __ATOMIC_ACQUIRE)) {
		size_t n = read_exact(d->ffmpeg_pipe, scratch, d->frame_size_bytes);
		if (n != d->frame_size_bytes) {
			ms_warning("msmoviecam: short read from ffmpeg (%zu/%zu); pipe closed", n, d->frame_size_bytes);
			break;
		}
		pthread_mutex_lock(&d->lock);
		memcpy(d->current_frame, scratch, d->frame_size_bytes);
		d->frame_ready = 1;
		pthread_mutex_unlock(&d->lock);
	}
	ms_free(scratch);
	return NULL;
}

static void moviecam_spawn_ffmpeg(MovieCamData *d) {
	char cmd[2200];
	/* -nostdin: never read from our stdin (we only want stdout)
	 * -stream_loop -1: loop input indefinitely
	 * -re: throttle to source frame rate (avoids burst buffering)
	 * -vf scale=W:H: force output size
	 * -r FPS: force output framerate
	 * -f rawvideo -pix_fmt yuv420p: raw planar YUV stream
	 * trailing '-': write to stdout
	 */
	snprintf(cmd, sizeof(cmd),
	         "%s -hide_banner -loglevel warning -nostdin "
	         "-stream_loop -1 -re -i \"%s\" "
	         "-vf scale=%d:%d -r %g -an "
	         "-f rawvideo -pix_fmt yuv420p -",
	         d->ffmpeg_bin, d->video_path,
	         d->vsize.width, d->vsize.height, (double)d->fps);
	ms_message("msmoviecam: starting ffmpeg: %s", cmd);
	d->ffmpeg_pipe = popen(cmd, "r");
	if (!d->ffmpeg_pipe) {
		ms_error("msmoviecam: popen(ffmpeg) failed: %s", strerror(errno));
	}
}

static void moviecam_read_env(MovieCamData *d) {
	const char *p;
	p = getenv("MSMOVIECAM_VIDEO");
	if (p && *p) strncpy(d->video_path, p, sizeof(d->video_path) - 1);
	p = getenv("MSMOVIECAM_FFMPEG");
	strncpy(d->ffmpeg_bin, (p && *p) ? p : "ffmpeg", sizeof(d->ffmpeg_bin) - 1);
	p = getenv("MSMOVIECAM_W");   if (p && *p) d->vsize.width  = atoi(p);
	p = getenv("MSMOVIECAM_H");   if (p && *p) d->vsize.height = atoi(p);
	p = getenv("MSMOVIECAM_FPS"); if (p && *p) d->fps = (float)atof(p);
}

static void moviecam_init(MSFilter *f) {
	MovieCamData *d = (MovieCamData *)ms_new0(MovieCamData, 1);
	d->vsize.width = MSMOVIECAM_DEFAULT_W;
	d->vsize.height = MSMOVIECAM_DEFAULT_H;
	d->fps = MSMOVIECAM_DEFAULT_FPS;
	pthread_mutex_init(&d->lock, NULL);
	moviecam_read_env(d);
	f->data = d;
}

static void moviecam_uninit(MSFilter *f) {
	MovieCamData *d = (MovieCamData *)f->data;
	pthread_mutex_destroy(&d->lock);
	ms_free(d);
}

static void moviecam_preprocess(MSFilter *f) {
	MovieCamData *d = (MovieCamData *)f->data;
	d->frame_size_bytes = (size_t)d->vsize.width * (size_t)d->vsize.height * 3 / 2;
	d->current_frame = (uint8_t *)ms_malloc0(d->frame_size_bytes);
	d->pic = ms_yuv_buf_alloc(&d->pict, d->vsize.width, d->vsize.height);
	memset(d->pic->b_rptr, 0, d->pic->b_wptr - d->pic->b_rptr);
	d->frame_index = 0;
	d->starttime = 0;
	d->frame_ready = 0;
	__atomic_store_n(&d->running, 1, __ATOMIC_RELEASE);

	if (d->video_path[0] == '\0') {
		ms_error("msmoviecam: MSMOVIECAM_VIDEO env var is not set — pipeline will emit blank frames");
		return;
	}
	moviecam_spawn_ffmpeg(d);
	if (d->ffmpeg_pipe) {
		pthread_create(&d->reader_thread, NULL, moviecam_reader_thread, d);
	}
}

static void moviecam_postprocess(MSFilter *f) {
	MovieCamData *d = (MovieCamData *)f->data;
	__atomic_store_n(&d->running, 0, __ATOMIC_RELEASE);
	if (d->ffmpeg_pipe) {
		pclose(d->ffmpeg_pipe);
		d->ffmpeg_pipe = NULL;
	}
	if (d->reader_thread) {
		pthread_join(d->reader_thread, NULL);
		d->reader_thread = 0;
	}
	if (d->current_frame) {
		ms_free(d->current_frame);
		d->current_frame = NULL;
	}
	if (d->pic) {
		freemsg(d->pic);
		d->pic = NULL;
	}
}

static void moviecam_copy_planes(MovieCamData *d) {
	const int w = d->pict.w, h = d->pict.h;
	const uint8_t *yp = d->current_frame;
	const uint8_t *up = yp + (size_t)w * h;
	const uint8_t *vp = up + (size_t)w * h / 4;
	for (int i = 0; i < h; i++) {
		memcpy(d->pict.planes[0] + i * d->pict.strides[0], yp + i * w, w);
	}
	for (int i = 0; i < h / 2; i++) {
		memcpy(d->pict.planes[1] + i * d->pict.strides[1], up + i * (w / 2), w / 2);
		memcpy(d->pict.planes[2] + i * d->pict.strides[2], vp + i * (w / 2), w / 2);
	}
}

static void moviecam_process(MSFilter *f) {
	MovieCamData *d = (MovieCamData *)f->data;
	float elapsed;

	ms_filter_lock(f);
	if (d->starttime == 0) d->starttime = f->ticker->time;
	elapsed = (float)(f->ticker->time - d->starttime);

	if ((elapsed * d->fps / 1000.0f) > d->frame_index) {
		mblk_t *om;
		pthread_mutex_lock(&d->lock);
		if (d->frame_ready) {
			moviecam_copy_planes(d);
		}
		pthread_mutex_unlock(&d->lock);
		om = dupb(d->pic);
		mblk_set_timestamp_info(om, (uint32_t)(f->ticker->time * 90));
		ms_queue_put(f->outputs[0], om);
		d->frame_index++;
	}
	ms_filter_unlock(f);
}

static int moviecam_set_vsize(MSFilter *f, void *arg) {
	MovieCamData *d = (MovieCamData *)f->data;
	d->vsize = *(MSVideoSize *)arg;
	return 0;
}

static int moviecam_get_vsize(MSFilter *f, void *arg) {
	MovieCamData *d = (MovieCamData *)f->data;
	*(MSVideoSize *)arg = d->vsize;
	return 0;
}

static int moviecam_set_fps(MSFilter *f, void *arg) {
	MovieCamData *d = (MovieCamData *)f->data;
	ms_filter_lock(f);
	d->fps = *(float *)arg;
	d->frame_index = 0;
	d->starttime = 0;
	ms_filter_unlock(f);
	return 0;
}

static int moviecam_get_fps(MSFilter *f, void *arg) {
	MovieCamData *d = (MovieCamData *)f->data;
	*(float *)arg = d->fps;
	return 0;
}

static int moviecam_get_pix_fmt(BCTBX_UNUSED(MSFilter *f), void *arg) {
	*(MSPixFmt *)arg = MS_YUV420P;
	return 0;
}

static MSFilterMethod moviecam_methods[] = {
    {MS_FILTER_SET_VIDEO_SIZE, moviecam_set_vsize},
    {MS_FILTER_GET_VIDEO_SIZE, moviecam_get_vsize},
    {MS_FILTER_SET_FPS,        moviecam_set_fps},
    {MS_FILTER_GET_FPS,        moviecam_get_fps},
    {MS_FILTER_GET_PIX_FMT,    moviecam_get_pix_fmt},
    {0, NULL},
};

static MSFilterDesc ms_moviecam_desc = {
    MS_FILTER_PLUGIN_ID,
    "MSMovieCam",
    "Reads an mp4/mov via ffmpeg and emits raw YUV420p frames",
    MS_FILTER_OTHER,
    NULL,
    0,
    1,
    moviecam_init,
    moviecam_preprocess,
    moviecam_process,
    moviecam_postprocess,
    moviecam_uninit,
    moviecam_methods,
    0,
};

static void moviecam_detect(MSWebCamManager *obj);

static void moviecam_cam_init(MSWebCam *cam) {
	cam->name = ms_strdup("MovieCam (file via ffmpeg)");
}

static MSFilter *moviecam_create_reader(MSWebCam *obj) {
	return ms_factory_create_filter_from_desc(ms_web_cam_get_factory(obj), &ms_moviecam_desc);
}

static MSWebCamDesc ms_moviecam_webcam_desc = {
    "MovieCam",
    &moviecam_detect,
    &moviecam_cam_init,
    &moviecam_create_reader,
    NULL,
    NULL,
};

static void moviecam_detect(MSWebCamManager *obj) {
	/* Always advertise the cam — the caller decides whether to select it. */
	MSWebCam *cam = ms_web_cam_new(&ms_moviecam_webcam_desc);
	ms_web_cam_manager_add_cam(obj, cam);
}

#ifdef _MSC_VER
#define MS_PLUGIN_DECLARE(type) extern "C" __declspec(dllexport) type
#else
#define MS_PLUGIN_DECLARE(type) type
#endif

MS_PLUGIN_DECLARE(void) libmsmoviecam_init(MSFactory *factory) {
	ms_factory_register_filter(factory, &ms_moviecam_desc);
	MSWebCamManager *cam_mgr = ms_factory_get_web_cam_manager(factory);
	if (cam_mgr) {
		ms_web_cam_manager_register_desc(cam_mgr, &ms_moviecam_webcam_desc);
	}
	ms_message("msmoviecam plugin registered (MovieCam webcam)");
}
