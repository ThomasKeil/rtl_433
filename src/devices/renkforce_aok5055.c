
/**
 * Renforce AOK-5055 protocol.
 * 
 * The analyzation and documentation of the packages was done by https://github.com/Rotzbua and 
 * is documented here: https://github.com/Rotzbua/reverse_engineering_weatherstation_conrad#package-format
 * 
 * The sensor sends 96 bits in 24 nibbles.
 * Format:
 * PPPPPPRRBTTTHHVVVSSDCCpp
 * 
 * P: Preamble, always aaa598
 * R: Random ID that changes every time the battery is changed
 * B: Battery status
 * T: Temperature in °C
 * H: Humidity
 * V: Rain volume
 * S: Wind speed
 * D: Wind direction
 * C: Checksum
 * p: Pause
 * 
 * Example: aaa5980f00905305e02da380
 * 
 */
#include "decoder.h"

// The lenght of a message in bytes
#define AOK5055_MESSAGE_LEN 12

// The lenght of the preamble in bits
#define AOK5055_MESSAGE_PREAMBLELEN  3 * 8

// How often needs the message to be repeated 
#define AOK5055_MINREPEATS  4

#define AOK5055_MILLIMETER_PER_STEP 0.75

// The preamble of the message. These re the nibbles 0xaaa598
static unsigned char preamble[3] = { 0xaa, 0xa5, 0x98 };

// A lookup table to convert the direction-nibble (thus sixteen values)
// to a nice direction.
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

void bytes_tohex(unsigned char * in, size_t insz, char * out, size_t outsz)
{
    unsigned char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for(; pin < in+insz; pout +=3, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
        pout[2] = ':';
        if (pout + 3 - out > outsz){
            /* Better to truncate output string than overflow buffer */
            /* it would be still better to either return a status */
            /* or ensure the target buffer is large enough and it never happen */
            break;
        }
    }
    pout[-1] = 0;
}

static int renkforce_aok5055_callback(r_device *decoder, bitbuffer_t *bitbuffer)
{
    data_t *data;

    unsigned char bytes[AOK5055_MESSAGE_LEN * AOK5055_MINREPEATS + 1]; // aligned packet data
    unsigned char raw[AOK5055_MESSAGE_LEN * 3 + 1]; // Two chars plus ":" = 3
    
    bitbuffer_invert(bitbuffer);

    // Check if the preamble 0xaaa598 is found at all
	unsigned int bitpos = bitbuffer_search(bitbuffer, 0, 0, preamble, AOK5055_MESSAGE_PREAMBLELEN);
    if (bitpos == bitbuffer->bits_per_row[0]) {
        // Not found
        return 0;
    }

    // Check if the row is long enough to contain the repeats
    if (bitpos + AOK5055_MINREPEATS * AOK5055_MESSAGE_LEN * 8 > bitbuffer->bits_per_row[0]) {
        return 0;
    }

    bitbuffer_extract_bytes(bitbuffer, 0, bitpos, bytes, AOK5055_MESSAGE_LEN * 8 * AOK5055_MINREPEATS);
    
    // bitbuffer_print(bitbuffer);

 
    // See if the message is repated AOK5055_MINREPEATS in the row.
    // Don't compare the last byte since the very last time it differs and "pause" is irrelevat
    // for the values anyways
    for (int position=0; position<AOK5055_MESSAGE_LEN - 1; position++) {
        for (int repeat=1; repeat <= AOK5055_MINREPEATS - 1; repeat++) {
            if (bytes[position] != bytes[position + (AOK5055_MESSAGE_LEN * repeat)]) {
                return 0;
            }
        }
    }

    bytes_tohex(bytes, 18, raw, 37);

    int humidity = bytes[6];
    int temperature_c = ((bytes[4] & 0x0f) << 8) | bytes[5];
    int rain_steps = ((bytes[7]) << 4) | ((bytes[8]) >> 4);
    float temperature = (float)temperature_c / 10.0;
    int wind_speed = ((bytes[8] & 0x0f) << 8) | (bytes[9] >> 4);
    double rain_mm = rain_steps * AOK5055_MILLIMETER_PER_STEP;
    int wind_direction = (bytes[9] & 0x0f);
    double wind_degrees = wind_direction * 22.5;
    uint8_t battery = (bytes[4] & 0xf0) == 0xf0; 

    data = data_make(
            "model", "", DATA_STRING, "Renkforce AOK5055",
            "temperature", "Temperature", DATA_FORMAT, "%.1f C", DATA_DOUBLE, temperature,
            "humidity", "Humidity", DATA_FORMAT, "%u %%", DATA_INT, humidity,
            "wind_direction", "Wind direction", DATA_STRING, direction_lookup[wind_direction],
            "wind_degrees", "Wind degrees", DATA_FORMAT, "%.1f °", DATA_DOUBLE, wind_degrees,
            "wind_speed", "Wind speed", DATA_FORMAT, "%u km/h", DATA_INT, wind_speed,
            "rain_volume", "Rain volume", DATA_FORMAT, "%.1f mm", DATA_DOUBLE, rain_mm,
            "battery", "Battery", DATA_STRING, battery ? "LOW" : "OK",
            "raw", "Raw", DATA_STRING, raw,
            NULL);

    decoder_output_data(decoder, data);
    return 1;
}

static char *renkforce_aok5055_output_fields[] = {
    "temperature",
    "humidity",
    "wind_direction",
    "wind_degrees",
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

