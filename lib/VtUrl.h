#ifndef VT_URL_H
#define VT_URL_H 1

// forward declarations
struct VtUrl;
struct VtObject;



struct VtUrl* VtUrl_new(void);

/** Get a reference counter */
void VtUrl_get(struct VtUrl *FileScan);


/** put a reference counter */
void VtUrl_put(struct VtUrl **FileScan);

void VtUrl_setApiKey(struct VtUrl *file_scan, const char *api_key);
int VtUrl_scan(struct VtUrl *file_scan, const char *file_path);
int VtUrl_rescanHash(struct VtUrl *file_scan, const char *hash);
int VtUrl_report(struct VtUrl *file_scan, const char *hash);

struct VtResponse * VtUrl_getResponse(struct VtUrl *file_scan);
#endif