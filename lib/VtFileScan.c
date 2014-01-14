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
// 	.obj_from_json      = VtFileScan_objectFromJSON,
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

void VtFileScan_setApiKey(struct VtFileScan *file_scan, const char *api_key)
{

	if (file_scan->api_key)
		free(file_scan->api_key);

	file_scan->api_key = strdup(api_key);
}

int VtFileScan_scan(struct VtFileScan *file_scan, const char *file_path)
{

	CURL *curl;
	CURLcode res;
	int ret = 0;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	json_t *json_data = NULL,  *ack_json = NULL;
	static const char header_buf[] = "Expect:";
	json_error_t json_error;
	
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


	// set size of upload
// 	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);
	
	/* enable verbose for easier tracing */ 
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb); // callback for data
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
	// 	fclose(fp);
	
	json_data =json_loads(file_scan->buffer, 0, &json_error);
	if (!json_data) {
		ERROR("Parsing\n");
		ret = -1;
		goto cleanup;
	}
	
	ack_json = json_object_get(json_data, "ack");
	if (ack_json) {
	} else {
		// Parse error
		ret = -1;
	}
	
	cleanup:
	if (json_data) {
		json_decref(json_data);
	}

	/* always cleanup */
	curl_easy_cleanup(curl);

	if (formpost)
		curl_formfree(formpost);  // cleanup the formpost chain

	if (headerlist)
		curl_slist_free_all (headerlist); // free headers
	
	return ret;
}
