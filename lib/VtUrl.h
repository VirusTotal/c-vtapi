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

/**
 * @brief Scan URL 
 * 
 * @param VtUrl   Url scan object
 * @param url    URL to scan
 * @return int  0 if OK or error code
 */

int VtUrl_scan(struct VtUrl *, const char *url);


/**
 * @brief get the report of the URL scan
 * 
 * @param VtUrl scan object
 * @param url  URL to get report on
 * @param scan set to true if you wish to rescan
 * @param all_info  set true if you wall aditional info.  (Private API Key Only) 
 * @return int
 */
int VtUrl_report(struct VtUrl *, const char *url, bool scan, bool all_info);

struct VtResponse * VtUrl_getResponse(struct VtUrl *file_scan);
#endif