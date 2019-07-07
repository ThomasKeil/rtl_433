
#include "decoder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Hypothetical template device
 *
 * Message is 68 bits long
 * Messages start with 0xAA
 * The message is repeated as 5 packets,
 * require at least 3 repeated packets.
 *
 */
const char* hexString(unsigned char *bytes, int bytesLength) 
{ 
    char lookup[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' }; 
    char *s = malloc(sizeof(char) * (bytesLength * 2 + 1)); 
    for (int i = 0; i < bytesLength; i++) { 
        s[i*2] =       lookup[(bytes[i] >> 4) & 0xF]; 
        s[i * 2 + 1] = lookup[bytes[i] & 0xF]; 
    } 
    s[bytesLength * 2] = 0;
    return s; 
}

#define AOK5055_BITLEN      96
#define AOK5055_STARTBYTE   0xAA
#define AOK5055_MINREPEATS  3

#define MYDEVICE_MSG_TYPE    0x10
#define MYDEVICE_CRC_POLY    0x07
#define MYDEVICE_CRC_INIT    0x00


static unsigned char preamble[3] = { 0xaa, 0xa5, 0x98 };
static unsigned char direction_lookup[16][4] = {
        "  N",
        "NNO",
        " NO",
        "ONO",
        "  O",
        "OSO",
        " SO",
        "SSO",
        "  S",
        "SSW",
        "SWW",
        " SW",
        "  W",
        "WNW",
        " NW",
        "NNW"
};

static int renkforce_aok5055_callback(r_device *decoder, bitbuffer_t *bitbuffer)
{
    data_t *data;

	bitrow_t *bb = bitbuffer->bb;
	unsigned bitpos = 0;
	unsigned bits = bitbuffer->bits_per_row[0];
    unsigned char bytes[18]; // aligned packet data

    // 24 Nibbles
    // aaa598 0f00905305e02da380
    
    bitbuffer_invert(bitbuffer);

	// Search for only 22 bits to cope with inverted frames and
	// the missing final preamble bit with RFM69 transmissions.
	bitpos = bitbuffer_search(bitbuffer, 0, bitpos, preamble, 24);

    if (bitpos == bitbuffer->bits_per_row[0]) {
        return 0;
    }

    bitbuffer_extract_bytes(bitbuffer, 0, bitpos, bytes, 12 * 8);

    int humidity = bytes[6];
    int temperature_c = ((bytes[4] & 0x0f) << 8) | bytes[5];
    int rain_steps = ((bytes[7]) << 4) | ((bytes[8]) >> 4);
    float temperature = temperature_c / 10;
    int wind_speed = ((bytes[8] & 0x0f) << 8) | (bytes[9] >> 4);
    double rain_mm = rain_steps * 0.75;
    int wind_direction = (bytes[9] & 0x0f);


    data = data_make(
            "model", "", DATA_STRING, "Renkforce AOK5055",
            "temperature", "Temperature", DATA_FORMAT, "%.1f C", DATA_DOUBLE, temperature,
            "humidity", "Humidity", DATA_FORMAT, "%u %%", DATA_INT, humidity,
            "wind_direction", "Wind direction", DATA_STRING, direction_lookup[wind_direction],
            "wind_speed", "Wind speed", DATA_FORMAT, "%u km/h", DATA_INT, wind_speed,
            "rain_volume", "Rain volume", DATA_FORMAT, "%.1f mm", DATA_DOUBLE, rain_mm,
            "battery", "Battery", DATA_INT, 1,
            "raw", "Raw", DATA_STRING, hexString(bytes, 12),
            NULL);

    decoder_output_data(decoder, data);
    return 1;
}

static char *renkforce_aok5055_output_fields[] = {
    "temperature",
    "humidity",
    "wind_direction",
    "wind_speed",
    "rain_volume",
    "battery",
    "raw",
    NULL
};

r_device renkforce_aok5505 = {
    .name           = "Renkforce AOK-5055",
    .modulation     = OOK_PULSE_PWM,
    .short_width    = 490,
    .long_width     = 966,
    .reset_limit    = 7000,
    .decode_fn      = &renkforce_aok5055_callback,
    .fields         = renkforce_aok5055_output_fields,

};
