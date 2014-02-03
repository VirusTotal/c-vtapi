#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>

#include "VtResponse.h"
#include "VtComments.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); 

void print_usage(const char *prog_name)
{
	printf("%s < --apikey YOUR_API_KEY >  [ --resource ] [ --get ]  [ --put \"<comments>\" ] < --before YYYYMMDDHHSS >\n", prog_name);
	printf("  --apikey YOUR_API_KEY   Your virus total API key.  This arg 1st \n");
	printf("  --resource              Hash your looking for\n");
	printf("  --get                   Get commnets of resource\n");
	printf("  --put 'comments'        'comments' to add to resource\n");
	printf("  --before 'YYYYMMDDHHSS'  datetime token\n");

}

int main(int argc, char * const *argv)
{
	int c;
	int ret = 0;
	struct VtComments *comments;
	struct VtResponse *response;
	char *str = NULL;
	char *api_key = NULL;
	bool get = true;


	if (argc < 2) {
		print_usage(argv[0]);
		return 0;
	}

	comments = VtComments_new();

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"apikey",  required_argument,     0,  'a'},
			{"before",  required_argument,     0,  'b'},
			{"put",  required_argument,    0,  'p' },
			{"resource",  required_argument,    0,  'r' },
			{"get",  no_argument,     0,  'g'},
			{"verbose", optional_argument,  0,  'v' },
			{"help", optional_argument,  0,  'h' },
			{0,         0,                 0,  0 }
		};

		c = getopt_long_only(argc, argv, "",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				api_key = strdup(optarg);
				printf(" apikey: %s \n", optarg);
				VtComments_setApiKey(comments, optarg);
				break;
			case 'r':
				printf(" resource: %s \n", optarg);
				VtComments_setResource(comments, optarg);
				break;
			case 'b':
				printf(" before: %s \n", optarg);
				VtComments_setBefore(comments, optarg);
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			case 'p':
				get = false;
				VtComments_add(comments, optarg);
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
		goto cleanup;
	}

	if (get) {
		ret = VtComments_retrieve(comments);

		if (ret) {
			printf("Error: %d \n", ret);
		} else {
			response = VtComments_getResponse(comments);
			str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
			if (str) {
				printf("Response:\n%s\n", str);
				free(str);
			}
			VtResponse_put(&response);
		}
	} else {
		// comments put in optarg parsing
	}

	cleanup:
	DBG("Cleanup\n");
	VtComments_put(&comments);
	if (api_key)
		free(api_key);
	return 0;
}
