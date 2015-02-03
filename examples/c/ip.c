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

#include "VtIpAddr.h"
#include "VtResponse.h"


#define DBG(FMT,ARG...) fprintf(stderr, "%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG);

void print_usage(const char *prog_name) {
  printf("%s < --apikey YOUR_API_KEY >  < --report  1.2.3.4. --> \n", prog_name);
  printf("  --apikey YOUR_API_KEY   Your virus total API key.  This arg 1st \n");
  printf("  --report    get report for IP Adress\n");
  printf("  --verbose   be verbose\n");
  printf("  --help      print this help message\n");
}

int main(int argc, char * const *argv) {
  int c;
  int ret = 0;
  struct VtIpAddr *ip_report;
  struct VtResponse *response;
  char *str = NULL;
  char *api_key = NULL;


  if (argc < 2) {
    print_usage(argv[0]);
    return 0;
  }

  ip_report = VtIpAddr_new();

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"report",  required_argument,    0,  'r' },
      {"apikey",  required_argument,     0,  'a'},
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
      VtIpAddr_setApiKey(ip_report, optarg);
      break;

    case 'r':
      if (!api_key) {
        printf("Must set --apikey first\n");
        exit(1);
      }

      ret = VtIpAddr_report(ip_report, optarg);
      DBG("rescan ret=%d\n", ret);
      if (ret) {
        printf("Error: %d \n", ret);
      } else {
        response = VtIpAddr_getResponse(ip_report);
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

  DBG("Cleanup\n");
  VtIpAddr_put(&ip_report);
  if (api_key)
    free(api_key);
  return 0;
}
