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

#ifndef VT_COMMENTS_H
#define VT_COMMENTS_H 1

#ifdef  __cplusplus
extern "C" {
#endif

// forward declarations
struct VtComments;
struct VtResponse;

/**
 * @brief Create new Comments object
 *
 * @param  ...
 * @return VtComments* pointer to object, or NULL if error occurred
 */
struct VtComments* VtComments_new(void);

/**
 * @brief Get a reference counter.
 *
 * @param vt_comments ...
 * @return void
 */
void VtComments_get(struct VtComments *vt_comments);


/**
 * @brief Put a reference counter
 *
 * @param vt_comments object
 * @return void
 */
void VtComments_put(struct VtComments **vt_comments);

/**
 * @brief Set API key
 *
 * @param vt_comments object to set API key
 * @param api_key the key
 * @return void
 */
void VtComments_setApiKey(struct VtComments *vt_comments, const char *api_key);


/**
 * @brief Set the Datetime token.  Allows you to iterate over all comments
 * on a specific item whenever it has been commented on more than 25 times.
 *
 * @param vt_comments comments object
 * @param value ...
 * @return void
 */
void VtComments_setBefore(struct VtComments *vt_comments, const char *value);

/**
 * @brief set the resource for which we will get/put comments
 *
 * @param vt_comments ...
 * @param value ...
 * @return int
 */

int VtComments_setResource(struct VtComments *vt_comments, const char *value);


/**
 * @brief Get the response object
 *
 * @param vt_comments comments object
 * @return VtResponse* response pointer or NULL with no response
 */
struct VtResponse * VtComments_getResponse(struct VtComments *vt_comments);

/**
 * @brief Add a comment.   Must 1st set the resource and API key to use this.
 *
 * @param vt_comments .comments object
 * @param comment comment text.  A valid ASCII or UTF-8 string.
 * @return int
 */
int VtComments_add(struct VtComments *vt_comments, const char *comment);


/**
 * @brief retrieve comments
 *
 * @param vt_comments comments object
 * @return int
 */
int VtComments_retrieve(struct VtComments *vt_comments);

#ifdef  __cplusplus
}
#endif /*cplusplus*/

#endif
