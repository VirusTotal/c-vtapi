/*
 C o*pyright 2014 VirusTotal S.L. All rights reserved.

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
#ifndef VT_API_PAGE_H
#define VT_API_PAGE_H 1

#ifdef  __cplusplus

class VpPageHandler_ops;
extern "C" {
#endif

#include <stdbool.h>

#include "VtObject.h"


/**
* @ingroup VtObject
* @defgroup VtApiPage  VtApiPage object for other API interfaces to inherit
* @{
*/



/**
	* Common Page Handler Header
	* This macro must be included as first member in every object,
	* that inherits this VtApiPage
	*/
#define API_OBJECT_COMMON \
  VT_OBJECT_COMMON; \
  struct VpPageHandler_ops *ph_ops;\
  char *buffer; \
  unsigned int buffer_size; \
  struct VtResponse *response; \
  char *api_key



struct Session;


/**
* @struct VtApiPage
* @brief A generic filter object that other more specialized handler objects will inherit.
* @brief This will give us a kind of polymorphism.
*/
struct VtApiPage {
  API_OBJECT_COMMON;

};

struct VtApiPage_ops {
  struct VtObject_ops *obj_ops; /// Parent Ops

};

/**
 * @brief Destructor.   This is only used internally not for use by users.
 *
 * @param obj object to be freed
 * @return int.  O for OK
 */
int VtApiPage_destructor(struct VtObject *obj);

struct VtApiPage* VtApiPage_alloc(struct VtApiPage_ops *ops);

struct VtApiPage* VtApiPage_new(void);


/**
 * @brief Relase a reference counter.  If reaches 0, object freed
 *
 * @param  Pointer to object pointer
 * @return void
 */
void VtApiPage_put(struct VtApiPage **);


/**
 * @brief Get a reference counter
 *
 * @param  API object pointer
 * @return void
 */
void VtApiPage_get(struct VtApiPage *);

/**
 * @brief Set the API key
 *
 * @param api object
 * @param key API KEY
 * @return void
 */
void VtApiPage_setApiKey(struct VtApiPage *api, const char *key);

/**
 * @brief Common callback for curl library.  Different functions within this libary use this.
 *
 * @param ptr pointer to data from curl
 * @param size ...
 * @param nmemb ...
 * @param userdata must be struct VtApiPage
 * @return size_t
 */
size_t __VtApiPage_WriteCb( char *ptr, size_t size, size_t nmemb, void *userdata);

/**
 * @brief Reset receive buffers
 *
 * @param api pointer to object
 * @return void
 */
void VtApiPage_resetBuffer(struct VtApiPage *api);


/** @}  */

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
