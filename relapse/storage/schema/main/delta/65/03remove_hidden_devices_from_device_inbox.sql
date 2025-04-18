/* Copyright 2021 The Matrix.org Foundation C.I.C
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


-- Remove messages from the device_inbox table which were orphaned
-- because a device was hidden using Relapse earlier than 1.47.0.
-- This runs as background task, but may take a bit to finish.

INSERT INTO background_updates (ordering, update_name, progress_json) VALUES
  (6503, 'remove_hidden_devices_from_device_inbox', '{}');
