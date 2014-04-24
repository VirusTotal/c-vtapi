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
#ifndef VT_URL_DIST
#define VT_URL_DIST 1

#ifdef  __cplusplus
extern "C" {
#endif

// forward declarations
struct VtUrlDist;
struct VtResponse;

/**
* @ingroup VtApiPage
* @defgroup VtUrlDist VtUrlDist URL Distribution service.  Requires private-API with permissions
* @{
*/
struct VtUrlDist* VtUrlDist_new(void);

/** Get a reference counter */
void VtUrlDist_get(struct VtUrlDist *FileScan);

/** put a reference counter */
void VtUrlDist_put(struct VtUrlDist **FileScan);

/**
 * @brief ...
 *
 * @param vt_udist ...
 * @param api_key ...
 * @return void
 */
void VtUrlDist_setApiKey(struct VtUrlDist *vt_udist, const char *api_key);


/**
 * @brief set all info flag
 *
 * @param vt_udist ...
 * @param value true/false
 * @return void
 */
void VtUrlDist_setAllInfo(struct VtUrlDist *vt_udist, bool value);

/**
 * @brief set after time
 *
 * @param vt_udist VtUrlDist ojbect pointer
 * @param value time sinc epoch in miliseconds
 * @return void
 */

void VtUrlDist_setAfter(struct VtUrlDist *vt_udist, unsigned long long value);

void VtUrlDist_setBefore(struct VtUrlDist *vt_udist, unsigned long long value);


/**
 * @brief set limit of results
 *
 * @param vt_udist VtUrlDist ojbect pointer
 * @param value ...
 * @return void
 */
void VtUrlDist_setLimit(struct VtUrlDist *vt_udist, int value);

struct VtResponse * VtUrlDist_getResponse(struct VtUrlDist *vt_udist);
int VtUrlDist_getDistribution(struct VtUrlDist *vt_udist);

int VtUrlDist_parse(struct VtUrlDist* url_dist,
                    void (*cb)(const char *url, unsigned long long timestamp, int total, int positives, json_t *raw_json, void *data),
                    void *user_data);

int VtUrlDist_process(struct VtUrlDist* url_dist,
                      void (*cb)(const char *url, unsigned long long timestamp, int total, int positives, json_t *raw_json, void *data),
                      void *user_data);

/**
*  @}
*/

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
