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

#ifndef VT_FILE_DIST
#define VT_FILE_DIST 1

#ifdef  __cplusplus
extern "C" {
#endif

struct VtResponse;
struct VtFileDist;

typedef void (*VtFileDistCb)(const char *url, unsigned long long timestamp,
  const char *sha256hash, const char *name, json_t *raw_json, void *data);


/**
 * @ingroup VtApiPage
 * @defgroup VtFileDist VtFileDist File Distribution service.  Requires private-API with permissions
 * @{
 */


struct VtFileDist* VtFileDist_new(void);


/**
 * @brief Get a reference counter
 *
 * @param obj FileDist object
 * @return void
 */
void VtFileDist_get(struct VtFileDist *obj);


/**
 * @brief Put a reference counter
 *
 * @param obj ...
 * @return void
 */
void VtFileDist_put(struct VtFileDist **obj);

/**
 * @brief Set the API key
 *
 * @param vt_dist  FileDist object
 * @param api_key api key
 * @return void
 */
void VtFileDist_setApiKey(struct VtFileDist *vt_dist, const char *api_key);

/**
 * @brief Set the reports flag.  If set true, reports returned
 *
 * @param vt_dist FileDist object
 * @param value true to enable.  false to disable
 * @return void
 */
void VtFileDist_setReports(struct VtFileDist *vt_dist, bool value);


/**
 * @brief Set the after time.  To recieve reports after X time. used to page over results
 *
 * @param vt_dist VtFileDist object
 * @param value unixtime
 * @return void
 */
void VtFileDist_setAfter(struct VtFileDist *vt_dist, unsigned long long  value);

/**
 * @brief Set the before time parameter.
 *
 * @param vt_dist VtFileDist object
 * @param value  unixtime
 * @return void
 */
void VtFileDist_setBefore(struct VtFileDist *vt_dist, unsigned long long  value);

/**
 * @brief Set max limit of results to return
 *
 * @param vt_dist VtFileDist
 * @param value  1 to 1000   results
 * @return void
 */
void VtFileDist_setLimit(struct VtFileDist *vt_dist, int value);


/**
 * @brief Get response object
 *
 * @param vt_dist VtFileDist object
 * @return VtResponse*
 */
struct VtResponse * VtFileDist_getResponse(struct VtFileDist *vt_dist);

/**
 * @brief Get the distrubution feed.  Then parse the results with VtFileDist_getResponse
 *
 * @param vt_dist VtFileDist object
 * @return int
 */

int VtFileDist_getDistribution(struct VtFileDist *vt_dist);

/**
 * @brief Process file distribution.  Internally calls VtFileDist_getDistribution
 *
 * @param vt_dist VtFileDist object
 * @param VtFileDistCb callback function, called on every result
 * @param user_data user data passed to callback function
 * @return int 0 for OK, or error code
 */
int VtFileDist_process(struct VtFileDist* vt_dist, VtFileDistCb, void *user_data);

/**
 *  @}
 */


#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
