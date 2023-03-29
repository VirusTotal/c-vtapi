/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef VT_FILE_SCAN_H
#define VT_FILE_SCAN_H 1

#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

// forward declarations
struct VtFile;
struct VtObject;
typedef void (*progress_changed_cb)(struct VtFile *, void *);

/**
* @ingroup VtApiPage
* @defgroup VtFile  VtFile object for scanning files.
* @{
*/


/**
 * @brief Create a new file object
 *
 * @param  ...
 * @return VtFile*  object pointer. or NULL on error allocating
 */
struct VtFile* VtFile_new(void);


/**
 * @brief Get a reference counter
 *
 * @param FileScan ...
 * @return void
 */
void VtFile_get(struct VtFile *FileScan);



/**
 * @brief Put a reference counter
 *
 * @param FileScan ...
 * @return void
 */
void VtFile_put(struct VtFile **FileScan);

/**
 * @brief Set API Key
 *
 * @param file_obj VtFile object pointer
 * @param api_key  Your API key
 * @return void
 */
void VtFile_setApiKey(struct VtFile *file_obj, const char *api_key);


/**
 * @brief Set the offset for the file/search  API.
 *
 * @param file_obj Object pointer
 * @param offset Offset string returned by virustotal.
 * @return void
 */
void VtFile_setOffset(struct VtFile *file_obj, const char *offset);


/**
 * @brief Set a callback function for progress changes.
 *
 * @param file VtFile object
 * @param progress_changed_cb callback function
 * @param data user data to be passed to callback
 * @return void
 */
void VtFile_setProgressCallback(struct VtFile *file,
  progress_changed_cb, void *data);

/**
 * @brief Get progress of upload/download
 *
 * @param file VTFil pointer
 * @param dltotal total download size
 * @param dlnow downloaded now
 * @param ul_total upload total
 * @param ul_now uploaded now
 * @return void
 */
void VtFile_getProgress(struct VtFile *file, int64_t *dltotal, int64_t *dlnow, int64_t *ul_total, int64_t *ul_now);

/**
 * @brief Cancel current upload/download
 *
 * @param file ...
 * @return int
 */

void VtFile_cancelOperation(struct VtFile* file);


/**
 * @brief Scan a file
 *
 * @param file_obj file object
 * @param file_path  path to file for scanning
 * @param notify_url POST to your server at this URL the report when scan is done. set to NULL if by default if not wanted
 * @return int
 */
int VtFile_scan(struct VtFile *file_obj, const char *file_path,  const char *notify_url);


/**
 * @brief Scan a file that is already buffered in memory
 *
 * @param file_scan file object
 * @param filename  file name that shows in VirusTotal report. Required paramter
 * @param memory_buffer memory buffer where the file is stored.
 *            This must me unmodified until the function returns
 * @param buffer_length length of the file
 * @param notify_url POST to your server at this URL the report
 *             when scan is done. set to NULL if by default if not wanted.
 * @return int
 */
int VtFile_scanMemBuf(struct VtFile *file_scan, const char *filename,
                      const unsigned char *memory_buffer,
                      unsigned int buffer_length,
                      const char *notify_url);

/**
 * @brief Rescan a previously submitted file or schedule a scan to be performed in the future.
 *
 * @param file_obj File scan object
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
int VtFile_rescanHash(struct VtFile *file_obj, const char *hash,
                      time_t date, int period, int repeat, const char *notify_url, bool notify_changes_only);

/**
 * @brief Delete a scheduled rescan task
 *
 * @param file_obj VtFile object pointer
 * @param hash  resoruce to remove
 * @return int
 */

int VtFile_rescanDelete(struct VtFile *file_obj,
                        const char *hash);

/**
 * @brief Fetch Report on a resource
 *
 * @param file_obj file object
 * @param resource  Hash, scan_id, or resource to fetch
 * @return int
 */
int VtFile_report(struct VtFile *file_obj, const char *resource);

struct VtResponse * VtFile_getResponse(struct VtFile *file_obj);


/**
 * @brief Search API
 *
 * @param file_obj file object
 * @param query Search query
 * @param cb Callback function pointer.  Will return hashes
 * @param user_data pointer to data pass to callback function.
 * @return int
 */
int VtFile_search(struct VtFile *file_obj, const char *query,
                  void (*cb)(const char *resource, void *data),
                  void *user_data);

#ifdef JANSSON_H



/**
 * @brief Get the clustering data
 * @brief Requires private-api permissions
 *
 * @param file_obj  File object
 * @param cluster_date   Clustering report date
 * @param cb write callback. will return a json_t object that you will need to parse
 * @param user_data user callback data
 * @return int.  0 for OK or error code
 */
int VtFile_clusters(struct VtFile *file_obj, const char *cluster_date,
                    void (*cb)(json_t *cluster_json, void *data),
                    void *user_data);
#endif


/**
 * @brief Download a file. callback function to write to memory, disk, network, etc
 * @brief Requires private-api permissions
 *
 * @param file_obj  File object
 * @param hash hash to download
 * @param cb write callback. Theis function will be called muliiple
 * @param user_data user callback data
 * @return int.  0 for OK or error code
 */
int VtFile_download(struct VtFile *file_obj, const char *hash,
  size_t (*cb)(char *ptr, size_t size, size_t nmemb, void *userdata), void *user_data);

/**
 * @brief Download and save to a file
 *
 * @param file_obj object
 * @param hash of file to download
 * @param out_file path to output file
 * @return int
 */
int VtFile_downloadToFile(struct VtFile *file_obj, const char *hash, const char *out_file);



int VtFile_uploadUrl(struct VtFile *file, char **url);

int VtFile_scanBigFile(struct VtFile *file_scan, const char * path);


/** @} */


#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
