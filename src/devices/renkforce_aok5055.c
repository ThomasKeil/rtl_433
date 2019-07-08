
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

// The lenght of a message in bits
#define AOK5055_MESSAGE_BITLEN      12 * 8

// The lenght of the preamble in bits
#define AOK5055_MESSAGE_PREAMBLELEN  3 * 8

// How often needs the message to be repeated 
#define AOK5055_MINREPEATS  3

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

static int renkforce_aok5055_callback(r_device *decoder, bitbuffer_t *bitbuffer)
{
    data_t *data;

    unsigned char bytes[18]; // aligned packet data
    
    bitbuffer_invert(bitbuffer);

    // Check if the preamble 0xaaa598 is found at all
	unsigned int bitpos = bitbuffer_search(bitbuffer, 0, 0, preamble, AOK5055_MESSAGE_PREAMBLELEN);
    if (bitpos == bitbuffer->bits_per_row[0]) {
        // Not found
        return 0;
    }


    bitbuffer_extract_bytes(bitbuffer, 0, bitpos, bytes, AOK5055_MESSAGE_BITLEN);

    int humidity = bytes[6];
    int temperature_c = ((bytes[4] & 0x0f) << 8) | bytes[5];
    int rain_steps = ((bytes[7]) << 4) | ((bytes[8]) >> 4);
    float temperature = temperature_c / 10;
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
