-- Device-facing service catalog reads start at the device membership table.
-- These indexes keep profile expansion bounded as the catalog grows.
CREATE INDEX access_profile_devices_device_id_idx ON access_profile_devices(device_id);
CREATE INDEX access_profile_services_service_id_idx ON access_profile_services(service_id);
