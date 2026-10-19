#import <Foundation/Foundation.h>

#include <assert.h>
#include <glib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static id idun_plist_test_parse (const uint8_t * data, int length, char ** error_message);

uint8_t *
idun_plist_test_to_binary_using_apple_implementation (const uint8_t * data, int length, char ** error_message,
    int * output_length)
{
  @autoreleasepool
  {
    uint8_t * result;
    id plist;
    NSData * bplist;
    size_t len;

    *error_message = NULL;
    *output_length = 0;

    plist = idun_plist_test_parse (data, length, error_message);
    if (plist == nil)
      return NULL;

    bplist = [NSPropertyListSerialization dataWithPropertyList:plist
                                                        format:NSPropertyListBinaryFormat_v1_0
                                                       options:0
                                                         error:nil];

    len = [bplist length];
    result = malloc (len);
    memcpy (result, [bplist bytes], len);
    *output_length = (int) len;

    return result;
  }
}

char *
idun_plist_test_to_xml_using_apple_implementation (const uint8_t * data, int length, char ** error_message)
{
  @autoreleasepool
  {
    id plist;
    NSData * xml;

    *error_message = NULL;

    plist = idun_plist_test_parse (data, length, error_message);
    if (plist == nil)
      return NULL;

    xml = [NSPropertyListSerialization dataWithPropertyList:plist
                                                     format:NSPropertyListXMLFormat_v1_0
                                                    options:0
                                                      error:nil];

    return strndup ([xml bytes], [xml length]);
  }
}

static id
idun_plist_test_parse (const uint8_t * data, int length, char ** error_message)
{
  id plist;
  NSData * input;
  NSPropertyListFormat format;
  NSError * error = nil;

  input = [NSData dataWithBytes:data length:(NSUInteger) length];

  plist = [NSPropertyListSerialization propertyListWithData:input
                                                    options:NSPropertyListImmutable
                                                     format:&format
                                                      error:&error];
  if (error != nil)
    *error_message = strdup ([[error localizedDescription] UTF8String]);

  return plist;
}
