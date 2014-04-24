#ifndef VT_FILE_SCAN_H
#define VT_FILE_SCAN_H 1

#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

// forward declarations
struct VtFile;
struct VtObject;

/**
* @ingroup VtApiPage
* @defgroup VtFile  VtFile object for secanning files.
* @{
*/


struct VtFile* VtFile_new(void);

/** Get a reference counter */
void VtFile_get(struct VtFile *FileScan);


/** put a reference counter */
void VtFile_put(struct VtFile **FileScan);

/**
 * @brief Set API Key
 * 
 * @param file_scan VtFile object pointer
 * @param api_key  Your API key
 * @return void
 */
void VtFile_setApiKey(struct VtFile *file_scan, const char *api_key);


/**
 * @brief Set the offset for the file/search  API.
 *
 * @param file_scan Object pointer
 * @param offset Offset string returned by virustotal.
 * @return void
 */
void VtFile_setOffset(struct VtFile *file_scan, const char *offset);

int VtFile_scan(struct VtFile *file_scan, const char *file_path);

/**
 * @brief Rescan a previously submitted file or schedule a scan to be performed in the future.
 *
 * @param file_scan File scan object
 * @param hash resouce to rescan
 * @param date default to 0, as not specified. If not specified, rescan immediately.
 * 		If specifed, it will be performed at the desired date.
 *      Private API permissions are required to specify this parameter
 * @param period  default 0, as not specified.   If specified period in days file
 *		to be rescaned. Private API permissions are required to specify this parameter
 * @param repeat default 0, as not specified.  If specified, file will be rescanned
 * every PERIOD paramater days, for REPEAT times.
 * @param notify_url default NULL, as not specified.  If specified, a POST will be sent to URL.
 *  Private API permissions are required to specify this parameter
 * @param notify_changes_only if notify_url set, only notify of changes
 * @return int
 */
int VtFile_rescanHash(struct VtFile *file_scan, const char *hash,
	time_t date, int period, int repeat, const char *notify_url, bool notify_changes_only);

/**
 * @brief Delete a scheduled rescan task
 *
 * @param file_scan VtFile object pointer
 * @param hash  resoruce to remove
 * @return int
 */

int VtFile_rescanDelete(struct VtFile *file_scan,
 const char *hash);

int VtFile_report(struct VtFile *file_scan, const char *hash);

struct VtResponse * VtFile_getResponse(struct VtFile *file_scan);


int VtFile_search(struct VtFile *file_scan, const char *query,
	void (*cb)(const char *resource, void *data),
	void *user_data);

#ifdef JANSSON_H
int VtFile_clusters(struct VtFile *file_scan, const char *cluster_date,
	void (*cb)(json_t *cluster_json, void *data),
	void *user_data);
#endif


int VtFile_download(struct VtFile *file_scan, const char *hash,
	size_t (*cb)(char *ptr, size_t size, size_t nmemb, void *userdata), void *user_data);

int VtFile_downloadToFile(struct VtFile *file_scan, const char *hash, const char *out_file);

/** @} */


#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
