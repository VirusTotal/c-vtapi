#ifndef VT_FILE_SCAN_H
#define VT_FILE_SCAN_H 1

// forward declarations
struct VtFileScan;
struct VtObject;



struct VtFileScan* VtFileScan_new(void);

/** Get a reference counter */
void VtFileScan_get(struct VtFileScan *FileScan);


/** put a reference counter */
void VtFileScan_put(struct VtFileScan **FileScan);

void VtFileScan_setApiKey(struct VtFileScan *file_scan, const char *api_key);
int VtFileScan_scan(struct VtFileScan *file_scan, const char *file_path);

#endif