#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "vtcapi-config.h"
#endif


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <jansson.h>
#include <stdbool.h>
#include <curl/curl.h>


#include "VtObject.h"
#include "VtApiPage.h"
#include "VtResponse.h"

#include "vtcapi_common.h"

struct VtUrl
{
	API_OBJECT_COMMON
};


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtUrl_constructor(struct VtObject *obj)
{
	struct VtUrl *vt_url = (struct VtUrl *)obj;

	DBG(DGB_LEVEL_MEM, " constructor %p\n", vt_url);

	return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtUrl_destructor(struct VtObject *obj)
{
	struct VtUrl *vt_url = (struct VtUrl *)obj;

	DBG(DGB_LEVEL_MEM, " destructor %p\n", vt_url);
	
	// Parent destructor
	return VtApiPage_destructor((struct VtObject *)obj);	
}



/** @} */


static struct VtObject_ops obj_ops = {
	.obj_type           = "file/scan",
	.obj_size           = sizeof(struct VtUrl),
	.obj_constructor    = VtUrl_constructor,
	.obj_destructor     = VtUrl_destructor,
// 	.obj_from_json      = VtUrl_objectFromJSON,
};

static struct VtUrl* VtUrl_alloc(struct VtObject_ops *ops)
{
	struct VtUrl *FileScan;

	FileScan = (struct VtUrl*) VtObject_alloc(ops);
	return FileScan;
}


struct VtUrl* VtUrl_new(void)
{
	struct VtUrl *FileScan = VtUrl_alloc(&obj_ops);

	return FileScan;
}

/** Get a reference counter */
void VtUrl_get(struct VtUrl *FileScan)
{
	VtObject_get((struct VtObject*) FileScan);
}

/** put a reference counter */
void VtUrl_put(struct VtUrl **FileScan)
{
	VtApiPage_put((struct VtApiPage**) FileScan);
}

static size_t write_cb( char *ptr, size_t size, size_t nmemb, void *userdata)
{
	size_t bytes = size * nmemb;  // total amount of data. 
	struct VtApiPage *page_hand = (struct VtApiPage *) userdata;
	unsigned int new_buff_size = page_hand->buffer_size + bytes;
	
	DBG(1, "Recv %zd bytes\n", bytes);
	
	page_hand->buffer = realloc(page_hand->buffer, new_buff_size+1);
	
	if (!page_hand->buffer) {
		ERROR("Out of memory\n");
		return 0;
	}
	
	page_hand->buffer[new_buff_size] = 0; // null term
	memcpy(page_hand->buffer + page_hand->buffer_size, ptr, bytes);
	
	
	page_hand->buffer_size = new_buff_size;
	return bytes;
}

void VtUrl_setApiKey(struct VtUrl *vt_url, const char *api_key)
{

	if (vt_url->api_key)
		free(vt_url->api_key);

	vt_url->api_key = strdup(api_key);
}


struct VtResponse * VtUrl_getResponse(struct VtUrl *vt_url)
{
	VtResponse_get(vt_url->response);
	return vt_url->response;
}

int VtUrl_scan(struct VtUrl *vt_url, const char *url)
{

	CURL *curl;
	CURLcode res;
	int ret = 0;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	static const char header_buf[] = "Expect:";
	
	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
		goto cleanup;
	}
	// initialize custom header list (stating that Expect: 100-continue is not wanted
	headerlist = curl_slist_append(headerlist, header_buf);

	DBG(1, "Api Key =  '%s'\n", vt_url->api_key);

	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "url",
			  CURLFORM_COPYCONTENTS,  url,
			  CURLFORM_END);
	if (ret)
		ERROR("Adding file %s\n", url);
	
	/* Fill in the filename field */ 
	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "url",
			  CURLFORM_COPYCONTENTS, url,
			  CURLFORM_END);
	if (ret)
		ERROR("Adding url %s\n", url);
	
	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "apikey",
			  CURLFORM_COPYCONTENTS, vt_url->api_key,
			  CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "url/scan");

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_url); // user arg
	
	
	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}
	
	DBG(1, "Page:\n%s\n",vt_url->buffer);

	vt_url->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(vt_url->response, vt_url->buffer);
	if (ret) {
		ERROR("Parsing JSON\n");
		goto cleanup;
	}
	
cleanup:
	/* always cleanup */
	curl_easy_cleanup(curl);

	if (formpost)
		curl_formfree(formpost);  // cleanup the formpost chain

	if (headerlist)
		curl_slist_free_all (headerlist); // free headers
	
	return ret;
}


int VtUrl_report(struct VtUrl *vt_url, const char *hash)
{
	
	CURL *curl;
	CURLcode res;
	int ret = 0;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	static const char header_buf[] = "Expect:";
	
	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
		goto cleanup;
	}
	// initialize custom header list (stating that Expect: 100-continue is not wanted
	headerlist = curl_slist_append(headerlist, header_buf);
	
	DBG(1, "hash to rescan'%s'\n", hash);
	DBG(1, "Api Key =  '%s'\n", vt_url->api_key);
	
	ret = curl_formadd(&formpost,
					   &lastptr,
					   CURLFORM_COPYNAME, "resource",
					   CURLFORM_COPYCONTENTS,  hash,
					   CURLFORM_END);
	if (ret)
		ERROR("Adding hash %s\n", hash);
	
	
	ret = curl_formadd(&formpost,
					   &lastptr,
					   CURLFORM_COPYNAME, "apikey",
					   CURLFORM_COPYCONTENTS, vt_url->api_key,
					   CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "url/report");
	
#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form
	
	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, vt_url); // user arg

	
	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}
	
	DBG(1, "Page:\n%s\n",vt_url->buffer);
	
	vt_url->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(vt_url->response, vt_url->buffer);
	if (ret) {
		ERROR("Parsing JSON\n");
		goto cleanup;
	}
	
cleanup:
	/* always cleanup */
	curl_easy_cleanup(curl);
	
	if (formpost)
		curl_formfree(formpost);  // cleanup the formpost chain
	
	if (headerlist)
		curl_slist_free_all (headerlist); // free headers
	
	return ret;
}


