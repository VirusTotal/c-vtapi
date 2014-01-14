#define _GNU_SOURCE




#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

#include "VtApiPage.h"
#include "vtcapi_common.h"


/**
* @name Constructor and Destructor
* @{
*/

/**
*  VtObjects constructor
*  @arg VtObject that was just allocated
*/
int VtApiPage_constructor(struct VtObject *obj)
{
	struct VtApiPage *page = (struct VtApiPage *)obj;

	DBG(DGB_LEVEL_MEM, " constructor %p\n", page);
	return 0;
}


/**
*  VtObjects destructor
*  @arg VtObject that is going to be free'd
*/
int VtApiPage_destructor(struct VtObject *obj)
{
	struct VtApiPage *page = (struct VtApiPage *)obj;

	DBG(DGB_LEVEL_MEM, " destructor %p\n", page);

	if (page->buffer)
		free(page->buffer);

	if (page->api_key)
		free(page->api_key);

	return 0;
}

/** @} */



static struct VtObject_ops vt_page_handler_obj_ops = {
	.obj_type           = "VtApiPage",
	.obj_size           = sizeof(struct VtApiPage),
	.obj_constructor    = VtApiPage_constructor,
	.obj_destructor     = VtApiPage_destructor,
};

static struct VtApiPage_ops vt_api_ops = {
	.obj_ops                = &vt_page_handler_obj_ops, // Parent ops

};

struct VtApiPage* VtApiPage_alloc(struct VtApiPage_ops *api_ops)
{
	struct VtApiPage *api;
	api = (struct VtApiPage*) VtObject_alloc(api_ops->obj_ops);
	api->obj_ops =  api_ops->obj_ops;

	return api;
}


struct VtApiPage* VtApiPage_new(void)
{
	struct VtApiPage *VtApiPage = VtApiPage_alloc(&vt_api_ops);

	return VtApiPage;
}

/** Get a reference counter */
void VtApiPage_get(struct VtApiPage *page)
{
	VtObject_get((struct VtObject*) page);
}

/** put a reference counter */
void VtApiPage_put(struct VtApiPage **page)
{
	VtObject_put((struct VtObject**) page);
}

