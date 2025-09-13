#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

static const char* TAG = "taric-esp32-example";

void app_main(void) {
    ESP_LOGI(TAG, "TARIC ESP32 example - TODO: integrate clients/c library");
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
