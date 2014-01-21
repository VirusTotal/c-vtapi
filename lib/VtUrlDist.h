#ifndef VT_URL_DIST
#define VT_URL_DIST 1


struct VtUrlDist;

struct VtUrlDist* VtUrlDist_new(void);

/** Get a reference counter */
void VtUrlDist_get(struct VtUrlDist *FileScan);

/** put a reference counter */
void VtUrlDist_put(struct VtUrlDist **FileScan);

void VtUrlDist_setApiKey(struct VtUrlDist *vt_udist, const char *api_key);
void VtUrlDist_setAllInfo(struct VtUrlDist *vt_udist, bool value);

void VtUrlDist_setAfter(struct VtUrlDist *vt_udist, unsigned long long  value);

void VtUrlDist_setBefore(struct VtUrlDist *vt_udist, unsigned long long  value);

void VtUrlDist_setLimit(struct VtUrlDist *vt_udist, unsigned long long  value);

struct VtResponse * VtUrlDist_getResponse(struct VtUrlDist *vt_udist);
int VtUrlDist_getDistribution(struct VtUrlDist *vt_udist);

int VtUrlDist_parse(struct VtUrlDist* url_dist, 
	void (*cb)(const char *url, unsigned long long timestamp, int total, int positives, json_t *raw_json, void *data),
	void *user_data);

int VtUrlDist_process(struct VtUrlDist* url_dist, 
	void (*cb)(const char *url, unsigned long long timestamp, int total, int positives, json_t *raw_json, void *data),
	void *user_data);

#endif