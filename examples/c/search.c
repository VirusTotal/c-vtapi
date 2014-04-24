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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>

#include "VtFile.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); 

void print_usage(const char *prog_name)
{
	printf("%s < --apikey YOUR_API_KEY >  [ --query 'QUERY STRING' ] [ --offset X ]\n", prog_name);
	printf("  --apikey YOUR_API_KEY   Your virus total API key.  This arg 1st \n");
	printf("  --query             'Query String'\n");
	printf("  --offset             Offset Value\n");
}

// Example data structure that can be passed to callback function
struct CallbackData
{
	int counter;
};




void search_callback(const char *resource, void *data)
{
	struct CallbackData *cb_data = (struct CallbackData *) data;

	cb_data->counter++;
	printf("------------- Result %d ----------------\n", cb_data->counter);
	printf("resource: %s \n", resource);
	printf("\n");
}

int main(int argc, char * const *argv)
{
	int c;
	int ret = 0;
	struct VtFile *file_scan;
	struct CallbackData cb_data = { .counter = 0 };
	char *query = NULL;
	int max_repeat = 1;


	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	file_scan = VtFile_new();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"apikey",  required_argument,     0,  'a'},
			{"query",  required_argument,    0,  'q' },
			{"repeat",  required_argument,    0,  'r' },
			{"offset",  required_argument,    0,  'o' },
			{"verbose", optional_argument,  0,  'v' },
			{"help", optional_argument,  0,  'h' },
			{0,         0,                 0,  0 }
		};

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				VtFile_setApiKey(file_scan, optarg);
				break;
			case 'q':
				query = strdup(optarg);
				break;
			case 'r':
				max_repeat = atoi(optarg);
				break;
			case 'h':
				print_usage(argv[0]);
				goto cleanup;
			case 'o':
				VtFile_setOffset(file_scan, optarg);
				break;
			case 'v':
				printf(" verbose selected\n");
				if (optarg)
					printf(" verbose level %s \n", optarg);
				break;
			default:
				printf("?? getopt returned character code 0%o ??\n", c);
			}
	} // end while

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

 	for ( ; max_repeat > 0; max_repeat--) {
		printf("Repeating %d times\n", max_repeat);
		ret = VtFile_search(file_scan, query, search_callback, &cb_data);
		if (ret) {
			printf("returned error %d\n", ret);
			break;
		}
	}
	cleanup:

	DBG("Cleanup\n");
	VtFile_put(&file_scan);
	if (query)
		free(query);
	return 0;
}
