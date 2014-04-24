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

#ifndef VT_RESPONSE_H
#define VT_RESPONSE_H 1


#ifdef  __cplusplus
extern "C" {
#endif

/**
* @ingroup VtObject
* @defgroup VtResponse VtResponse object.  All API responses stored here.
* @{
*/


/// Flag to include debug info in JSON if necessary
#define VT_JSON_FLAG_DEBUG   1 << 0

/// Indent JSON
#define VT_JSON_FLAG_INDENT  1 << 1

struct VtResponse;

struct VtResponse* VtResponse_new(void);


/**
 * @brief Get a reference counter.
 *
 * @param VtResponse Response object
 * @return void
 */
void VtResponse_get(struct VtResponse *VtResponse);


/**
 * @brief put a reference counter
 *
 * @param VtResponse ...
 * @return void
 */
void VtResponse_put(struct VtResponse **VtResponse);

/**
 * @brief get the _verbose_msg field of the JSON response
 *
 * @param response VTResponse object
 * @param buf  buffer to write the response into
 * @param buf_siz size of the buffer
 * @return char*
 */

char * VtResponse_getVerboseMsg(struct VtResponse *response, char *buf, int buf_siz);

/**
 * @brief Get the response code in the JSON response
 *
 * @param response VtResponse object
 * @param response_code  response code
 * @return int 0 if OK.  -1 if not found.
 */
int VtResponse_getResponseCode(struct VtResponse *response, int *response_code);

/**
 * @brief Get the raw JSON response.   The caller must free the returned string
 *
 * @param response VtResponse object
 * @param flags  set to 0,  or VT_JSON_FLAG_INDENT  to indent the json  for a human to read
 * @return char*   NULL if no response.  The caller must free the returned pointer to avoid a leak.
 */
char * VtResponse_toJSONstr(struct VtResponse *response, int flags);



/**
 * @brief Fill the response object from the JSON string
 *
 * @param response VtResponse object
 * @param json_str ...
 * @return int
 */
int VtResponse_fromJSONstr(struct VtResponse *response, const char *json_str);


/**
 * @brief Get an integer key/value pair within the JSON response
 *
 * @param response VtResponse object
 * @param key Key value to read
 * @param value  integer value returned
 * @return int
 */
int VtResponse_getIntValue(struct VtResponse *response, const char *key, int *value);

/**
 * @brief Get a string key/value pair in the JSON response
 *
 * @param response VtResponse object
 * @param key key to read
 * @return char*  string returned.  user must free this pointer to avoid a leak. Will return NULL if not found.
 */
char *VtResponse_getString(struct VtResponse *response, const char *key);


/**
 * @brief Get raw jansson response object
 *
 * @param response borrowed json_t pointer.
 * @return json_t*
 */
json_t * VtResponse_getJanssonObj(struct VtResponse *response);

/** @} */


#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
