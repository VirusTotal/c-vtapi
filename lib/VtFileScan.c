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

struct VtFileScan
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
int VtFileScan_constructor(struct VtObject *obj)
{
	struct VtFileScan *file_scan = (struct VtFileScan *)obj;

	DBG(DGB_LEVEL_MEM, " constructor %p\n", file_scan);

	return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtFileScan_destructor(struct VtObject *obj)
{
	struct VtFileScan *file_scan = (struct VtFileScan *)obj;

	DBG(DGB_LEVEL_MEM, " destructor %p\n", file_scan);
	
	// Parent destructor
	return VtApiPage_destructor((struct VtObject *)obj);	
}



/** @} */


static struct VtObject_ops obj_ops = {
	.obj_type           = "file/scan",
	.obj_size           = sizeof(struct VtFileScan),
	.obj_constructor    = VtFileScan_constructor,
	.obj_destructor     = VtFileScan_destructor,
};

static struct VtFileScan* VtFileScan_alloc(struct VtObject_ops *ops)
{
	struct VtFileScan *FileScan;

	FileScan = (struct VtFileScan*) VtObject_alloc(ops);
	return FileScan;
}


struct VtFileScan* VtFileScan_new(void)
{
	struct VtFileScan *FileScan = VtFileScan_alloc(&obj_ops);

	return FileScan;
}

/** Get a reference counter */
void VtFileScan_get(struct VtFileScan *FileScan)
{
	VtObject_get((struct VtObject*) FileScan);
}

/** put a reference counter */
void VtFileScan_put(struct VtFileScan **FileScan)
{
	VtApiPage_put((struct VtApiPage**) FileScan);
}



void VtFileScan_setApiKey(struct VtFileScan *file_scan, const char *api_key)
{
	// Call parent function
	return VtApiPage_setApiKey((struct VtApiPage *)file_scan, api_key);
}


struct VtResponse * VtFileScan_getResponse(struct VtFileScan *file_scan)
{
	VtResponse_get(file_scan->response);
	return file_scan->response;
}

int VtFileScan_scan(struct VtFileScan *file_scan, const char *file_path)
{

	CURL *curl;
	CURLcode res;
	int ret = 0;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	static const char header_buf[] = "Expect:";
	
	
	VtApiPage_resetBuffer((struct VtApiPage *) file_scan);

	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
		goto cleanup;
	}
	// initialize custom header list (stating that Expect: 100-continue is not wanted
	headerlist = curl_slist_append(headerlist, header_buf);

	DBG(1, "File to send '%s'\n", file_path);
	DBG(1, "Api Key =  '%s'\n", file_scan->api_key);

	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "file",
			  CURLFORM_FILE,  file_path,
			  CURLFORM_END);
	if (ret)
		ERROR("Adding file %s\n", file_path);
	
	/* Fill in the filename field */ 
	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "filename",
			  CURLFORM_COPYCONTENTS, file_path, // FIXME
			  CURLFORM_END);
	if (ret)
		ERROR("Adding filename %s\n", file_path);
	
	ret = curl_formadd(&formpost,
				 &lastptr,
			  CURLFORM_COPYNAME, "apikey",
			  CURLFORM_COPYCONTENTS, file_scan->api_key,
			  CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/scan");

#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form

	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg


	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}

	DBG(1, "Page:\n%s\n",file_scan->buffer);

	if (file_scan->response)
		VtResponse_put(&file_scan->response);

	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
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


int VtFileScan_rescanHash(struct VtFileScan *file_scan, const char *hash)
{
	
	CURL *curl;
	CURLcode res;
	int ret = 0;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	static const char header_buf[] = "Expect:";

	VtApiPage_resetBuffer((struct VtApiPage *) file_scan);

	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
		goto cleanup;
	}
	// initialize custom header list (stating that Expect: 100-continue is not wanted
	headerlist = curl_slist_append(headerlist, header_buf);
	
	DBG(1, "hash to rescan'%s'\n", hash);
	DBG(1, "Api Key =  '%s'\n", file_scan->api_key);
	
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
					   CURLFORM_COPYCONTENTS, file_scan->api_key,
					   CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/rescan");
	
#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form
	
	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg
	
	
	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}

	DBG(1, "Page:\n%s\n",file_scan->buffer);
	if (file_scan->response)
		VtResponse_put(&file_scan->response);

	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
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


int VtFileScan_report(struct VtFileScan *file_scan, const char *hash)
{
	
	CURL *curl;
	CURLcode res;
	int ret = 0;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	static const char header_buf[] = "Expect:";

	VtApiPage_resetBuffer((struct VtApiPage *) file_scan);
	curl = curl_easy_init();
	if (!curl) {
		ERROR("init curl\n");
		goto cleanup;
	}
	// initialize custom header list (stating that Expect: 100-continue is not wanted
	headerlist = curl_slist_append(headerlist, header_buf);
	
	DBG(1, "hash to rescan'%s'\n", hash);
	DBG(1, "Api Key =  '%s'\n", file_scan->api_key);
	
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
					   CURLFORM_COPYCONTENTS, file_scan->api_key,
					   CURLFORM_END);
	
	if (ret)
		ERROR("Adding key\n");
	
	curl_easy_setopt(curl, CURLOPT_URL, VT_API_BASE_URL "file/report");
	
#ifdef DISABLE_HTTPS_VALIDATION
	curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,0L); // disable validation
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost); // set form
	
	/* enable verbose for easier tracing */
    if (debug_level)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, __VtApiPage_WriteCb); // callback for data
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file_scan); // user arg

	
	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	DBG(1, "Perform done\n");
	/* Check for errors */
	if(res != CURLE_OK) {
		ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto cleanup;
	}
	
	DBG(1, "Page:\n%s\n",file_scan->buffer);

	if (file_scan->response)
		VtResponse_put(&file_scan->response);
	file_scan->response = VtResponse_new();
	ret = VtResponse_fromJSONstr(file_scan->response, file_scan->buffer);
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


