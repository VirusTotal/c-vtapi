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

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "c-vtapi_config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#endif

#include <time.h>
#include <jansson.h>
#include <stdbool.h>
#include <curl/curl.h>


#include "VtObject.h"
#include "VtApiPage.h"
#include "VtResponse.h"

#include "vtcapi_common.h"

/**
 * @brief URL object
 *
 */
struct VtUrl {
  API_OBJECT_COMMON;
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtUrl_constructor(struct VtObject *obj) {
  struct VtUrl *vt_url = (struct VtUrl *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_url);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtUrl_destructor(struct VtObject *obj) {
  struct VtUrl *vt_url = (struct VtUrl *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_url);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "VtUrl",
  .obj_size           = sizeof(struct VtUrl),
  .obj_constructor    = VtUrl_constructor,
  .obj_destructor     = VtUrl_destructor,
// 	.obj_from_json      = VtUrl_objectFromJSON,
};

static struct VtUrl* VtUrl_alloc(struct VtObject_ops *ops) {
  struct VtUrl *url_scan;

  url_scan = (struct VtUrl*) VtObject_alloc(ops);
  return url_scan;
}


struct VtUrl* VtUrl_new(void) {
  struct VtUrl *url_scan = VtUrl_alloc(&obj_ops);

  return url_scan;
}

/** Get a reference counter */
void VtUrl_get(struct VtUrl *url_scan) {
  VtObject_get((struct VtObject*) url_scan);
}

/** put a reference counter */
void VtUrl_put(struct VtUrl **url_scan) {
  VtApiPage_put((struct VtApiPage**) url_scan);
}

void VtUrl_setApiKey(struct VtUrl *vt_url, const char *api_key) {
  // Call parent function
  VtApiPage_setApiKey((struct VtApiPage *)vt_url, api_key);
}


struct VtResponse * VtUrl_getResponse(struct VtUrl *vt_url) {
  VtResponse_get(vt_url->response);
  return vt_url->response;
}

int VtUrl_scan(struct VtUrl *vt_url, const char *url) {

  CURL *curl = NULL;
  CURLcode res;
  int ret = 0;
  struct curl_slist *headerlist=NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;
  static const char header_buf[] = "Expect:";

  VtApiPage_resetBuffer((struct VtApiPage *) vt_url);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "Api Key =  '%s'\n", vt_url->api_key);

  mime = curl_mime_init(curl);
  if (!mime) {
    VT_ERROR("init curl mime\n");
    goto cleanup;
  }

  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, url, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding url %s\n", url);
  ret = curl_mime_name(part, "url");
  if (ret)
    VT_ERROR("Adding url multipart name %s\n", url);

  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, vt_url->api_key, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding key\n");
  ret = curl_mime_name(part, "apikey");
  if (ret)
    VT_ERROR("Adding apikey multipart name");

  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "url/scan");

#ifdef DISABLE_HTTPS_VALIDATION
  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* enable verbose for easier tracing */
  if (debug_level)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_url); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for VT_ERRORs */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",vt_url->buffer);

  // if a previous response
  if (vt_url->response)
    VtResponse_put(&vt_url->response);   // relase reference counter

  vt_url->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(vt_url->response, vt_url->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  curl_mime_free(mime);

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

  return ret;
}


int VtUrl_report(struct VtUrl *vt_url, const char *resource, bool scan, bool all_info) {

  CURL *curl = NULL;
  CURLcode res;
  int ret = 0;
  struct curl_slist *headerlist = NULL;
  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;
  static const char header_buf[] = "Expect:";

  VtApiPage_resetBuffer((struct VtApiPage *) vt_url);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);
  DBG(1, "Api Key =  '%s'\n", vt_url->api_key);

  mime = curl_mime_init(curl);
  if (!mime) {
    VT_ERROR("init curl mime\n");
    goto cleanup;
  }

  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, resource, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding resource %s\n", resource);
  ret = curl_mime_name(part, "resource");
  if (ret)
    VT_ERROR("Adding resource multipart name %s\n", resource);

  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, vt_url->api_key, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding key\n");
  ret = curl_mime_name(part, "apikey");
  if (ret)
    VT_ERROR("Adding key multipart name\n");

  if (scan) {
    part = curl_mime_addpart(mime);
    ret = curl_mime_data(part, "1", CURL_ZERO_TERMINATED);
    if (ret)
      VT_ERROR("Adding scan\n");
    ret = curl_mime_name(part, "scan");
    if (ret)
      VT_ERROR("Adding scan multipart name\n");
  }

  if (all_info) {
    part = curl_mime_addpart(mime);
    ret = curl_mime_data(part, "1", CURL_ZERO_TERMINATED);
    if (ret)
      VT_ERROR("Adding all_info\n");
    ret = curl_mime_name(part, "all_info");
    if (ret)
      VT_ERROR("Adding all_info multipart name\n");
  }


  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "url/report");

#ifdef DISABLE_HTTPS_VALIDATION
  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* enable verbose for easier tracing */
  if (debug_level)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_url); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for VT_ERRORs */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",vt_url->buffer);

  // if a previous response
  if (vt_url->response)
    VtResponse_put(&vt_url->response);   // relase reference counter
  vt_url->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(vt_url->response, vt_url->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  curl_mime_free(mime);

  if (headerlist)
    curl_slist_free_all (headerlist); // free headers

  return ret;
}
