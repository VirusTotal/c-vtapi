#ifndef VT_FILE_DIST
#define VT_FILE_DIST 1

#ifdef  __cplusplus
extern "C" {
#endif

struct VtFileDist* VtFileDist_new(void);

/** Get a reference counter */
void VtFileDist_get(struct VtFileDist *obj);

/** put a reference counter */
void VtFileDist_put(struct VtFileDist **obj);

void VtFileDist_setApiKey(struct VtFileDist *vt_udist, const char *api_key);

void VtFileDist_setReports(struct VtFileDist *vt_udist, bool value);

void VtFileDist_setAfter(struct VtFileDist *vt_udist, unsigned long long  value);

void VtFileDist_setBefore(struct VtFileDist *vt_udist, unsigned long long  value);

void VtFileDist_setLimit(struct VtFileDist *vt_udist, int value);

struct VtResponse * VtFileDist_getResponse(struct VtFileDist *vt_udist);

int VtFileDist_getDistribution(struct VtFileDist *vt_udist);

int VtFileDist_process(struct VtFileDist* url_dist,
	void (*cb)(const char *url, unsigned long long timestamp, const char *sha256hash, const char *name, json_t *raw_json, void *data),
	void *user_data);


#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
