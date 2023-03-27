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
#include "VtComments.h"

#include "vtcapi_common.h"

struct VtComments {
  API_OBJECT_COMMON;
  char *before; // comments before date
  char *resource;
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtComments_constructor(struct VtObject *obj) {
  struct VtComments *vt_comments = (struct VtComments *)obj;

  DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_comments);

  return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtComments_destructor(struct VtObject *obj) {
  struct VtComments *vt_comments = (struct VtComments *)obj;

  DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_comments);

  if (vt_comments->before)
    free(vt_comments->before);
  if (vt_comments->resource)
    free(vt_comments->resource);

  // Parent destructor
  return VtApiPage_destructor((struct VtObject *)obj);
}



/** @} */


static struct VtObject_ops obj_ops = {
  .obj_type           = "VtComments",
  .obj_size           = sizeof(struct VtComments),
  .obj_constructor    = VtComments_constructor,
  .obj_destructor     = VtComments_destructor,
// 	.obj_from_json      = VtComments_objectFromJSON,
};

static struct VtComments* VtComments_alloc(struct VtObject_ops *ops) {
  struct VtComments *vt_comments;

  vt_comments = (struct VtComments*) VtObject_alloc(ops);
  return vt_comments;
}


struct VtComments* VtComments_new(void) {
  struct VtComments *vt_comments = VtComments_alloc(&obj_ops);

  return vt_comments;
}

/** Get a reference counter */
void VtComments_get(struct VtComments *vt_comments) {
  VtObject_get((struct VtObject*) vt_comments);
}

/** put a reference counter */
void VtComments_put(struct VtComments **vt_comments) {
  VtApiPage_put((struct VtApiPage**) vt_comments);
}

void VtComments_setApiKey(struct VtComments *vt_comments, const char *api_key) {
  // Call parent function
  VtApiPage_setApiKey((struct VtApiPage *)vt_comments, api_key);
}


struct VtResponse * VtComments_getResponse(struct VtComments *vt_comments) {
  VtResponse_get(vt_comments->response);
  return vt_comments->response;
}

void VtComments_setBefore(struct VtComments *vt_comments, const char *value) {
  if (vt_comments->before)
    free(vt_comments->before);

  vt_comments->before = strdup(value);
}

int VtComments_setResource(struct VtComments *vt_comments, const char *value) {
  if (vt_comments->resource)
    free(vt_comments->resource);

  vt_comments->resource = strdup(value);

  return 0;
}


int VtComments_add(struct VtComments *vt_comments, const char *comment) {
  CURL *curl = NULL;
  CURLcode res;
  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;
  int ret = 0;
  struct curl_slist *headerlist=NULL;
  static const char header_buf[] = "Expect:";

  VtApiPage_resetBuffer((struct VtApiPage *) vt_comments);

  if (!vt_comments->resource) {
    VT_ERROR("Missing Resource. call VtComments_setResource() first\n");
    return -1;
  }

  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }
  // initialize custom header list (stating that Expect: 100-continue is not wanted
  headerlist = curl_slist_append(headerlist, header_buf);

  DBG(1, "Api Key =  '%s'\n", vt_comments->api_key);

  mime = curl_mime_init(curl);
  if (!mime) {
    VT_ERROR("init curl mime\n");
    goto cleanup;
  }

  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, vt_comments->resource, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding resource %s\n", vt_comments->resource);
  ret = curl_mime_name(part, "resource");
  if (ret)
    VT_ERROR("Adding resource multipart name %s\n", vt_comments->resource);

  /* Fill in the filename field */
  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, comment, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding comment %s\n", comment);
  ret = curl_mime_name(part, "comment");
  if (ret)
    VT_ERROR("Adding comment multipart name %s\n", comment);

  part = curl_mime_addpart(mime);
  ret = curl_mime_data(part, vt_comments->api_key, CURL_ZERO_TERMINATED);
  if (ret)
    VT_ERROR("Adding key\n");
  ret = curl_mime_name(part, "apikey");
  if (ret)
    VT_ERROR("Adding key multipart name\n");

  curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "comments/put");

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
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_comments); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",vt_comments->buffer);

  // if a previous response
  if (vt_comments->response)
    VtResponse_put(&vt_comments->response);   // relase reference counter

  vt_comments->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(vt_comments->response, vt_comments->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);

  curl_mime_free(mime);

  if (headerlist)
    curl_slist_free_all(headerlist); // free headers

  return ret;
}


int VtComments_retrieve(struct VtComments *vt_comments) {
  CURL *curl;
  CURLcode res;
  int ret = 0;
  char get_url[512];
  int len;

  if (!vt_comments->resource) {
    VT_ERROR("Missing Resource. call VtComments_setResource() first\n");
    return -1;
  }

  if (!vt_comments->api_key) {
    VT_ERROR("Missing APIKEY. call VtComments_setApiKey() first\n");
    return -1;
  }

  VtApiPage_resetBuffer((struct VtApiPage *) vt_comments);
  curl = curl_easy_init();
  if (!curl) {
    VT_ERROR("init curl\n");
    goto cleanup;
  }

  len = snprintf(get_url, sizeof(get_url)-1, VT_API_BASE_URL "comments/get?apikey=%s&resource=%s",
                 vt_comments->api_key, vt_comments->resource);
  if (len < 0) {
    VT_ERROR("sprintf\n");
    goto cleanup;
  }

  if (vt_comments->before) {
    len += ret = sprintf(get_url + len, "&before=%s", vt_comments->before);
    if (ret < 0) {
      VT_ERROR("sprintf before\n");
      goto cleanup;
    }
  }



  curl_easy_setopt(curl, CURLOPT_URL, get_url);

#ifdef DISABLE_HTTPS_VALIDATION
  curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  /* enable verbose for easier tracing */
  if (debug_level)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_comments); // user arg


  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);
  DBG(1, "Perform done\n");
  /* Check for errors */
  if(res != CURLE_OK) {
    VT_ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    goto cleanup;
  }

  DBG(1, "Page:\n%s\n",vt_comments->buffer);

  // if a previous response
  if (vt_comments->response)
    VtResponse_put(&vt_comments->response);   // relase reference counter
  vt_comments->response = VtResponse_new();
  ret = VtResponse_fromJSONstr(vt_comments->response, vt_comments->buffer);
  if (ret) {
    VT_ERROR("Parsing JSON\n");
    goto cleanup;
  }

cleanup:
  /* always cleanup */
  curl_easy_cleanup(curl);


  return ret;
}
