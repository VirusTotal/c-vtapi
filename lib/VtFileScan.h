#ifndef VT_FILE_SCAN_H
#define VT_FILE_SCAN_H 1

// forward declarations
struct VtFileScan;
struct VtObject;

/**
* @ingroup VtApiPage
* @defgroup VtFileScan  VtFileScan object for secanning files.
* @{
*/


struct VtFileScan* VtFileScan_new(void);

/** Get a reference counter */
void VtFileScan_get(struct VtFileScan *FileScan);


/** put a reference counter */
void VtFileScan_put(struct VtFileScan **FileScan);

/**
 * @brief Set API Key
 * 
 * @param file_scan VtFileScan object pointer
 * @param api_key  Your API key
 * @return void
 */
void VtFileScan_setApiKey(struct VtFileScan *file_scan, const char *api_key);
int VtFileScan_scan(struct VtFileScan *file_scan, const char *file_path);
int VtFileScan_rescanHash(struct VtFileScan *file_scan, const char *hash);
int VtFileScan_report(struct VtFileScan *file_scan, const char *hash);

struct VtResponse * VtFileScan_getResponse(struct VtFileScan *file_scan);

/** @} */
#endif