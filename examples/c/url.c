#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <stdbool.h>

#include "VtUrl.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG);

void print_usage(const char *prog_name) {
  printf("%s < --apikey YOUR_API_KEY >  [ --all-info ] [ --report-scan ]  [ --report URL ] [ --scan URL ]\n", prog_name);
  printf("  --apikey YOUR_API_KEY   Your virus total API key.  This arg 1st \n");
  printf("  --all-info              When doing a report, set allinfo flag\n");
  printf("  --report-scan           When doing a report, set scan flag\n");
  printf("  --scan URL              URL to scan. \n");
  printf("  --report URL            URL to report.\n");

}

int main(int argc, char * const *argv) {
  int c;
  int ret = 0;
  struct VtUrl *file_scan;
  struct VtResponse *response;
  char *str = NULL;
  char *api_key = NULL;
  bool all_info = false;
  bool report_scan = false;

  if (argc < 2) {
    print_usage(argv[0]);
    return 0;
  }

  file_scan = VtUrl_new();

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"scan",  required_argument,    0,  's' },
      {"report",  required_argument,    0,  'r' },
      {"apikey",  required_argument,     0,  'a'},
      {"report-scan",  no_argument,     0,  '1'},
      {"all-info",  no_argument,     0,  'i'},
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
      VtUrl_setApiKey(file_scan, optarg);
      break;

    case 's':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }

      ret = VtUrl_scan(file_scan, optarg);
      DBG("Filescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtUrl_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }
        VtResponse_put(&response);
      }
      break;
    case '1':
      report_scan = true;
      break;
    case 'i':
      all_info = true;
      break;
    case 'r':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }

      ret = VtUrl_report(file_scan, optarg, all_info, report_scan);
      DBG("rescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtUrl_getResponse(file_scan);
        str = VtResponse_toJSONstr(response, VT_JSON_FLAG_INDENT);
        if (str) {
          printf("Response:\n%s\n", str);
          free(str);
        }
        VtResponse_put(&response);
      }
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
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

  DBG("Cleanup\n");
  VtUrl_put(&file_scan);
  if (api_key)
    free(api_key);
  return 0;
}