/*
 * mobile_image_mounter.c
 * com.apple.mobile.mobile_image_mounter service implementation.
 *
 * Copyright (c) 2010-2019 Nikias Bassen, All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <plist/plist.h>

#include "mobile_image_mounter.h"
#include "property_list_service.h"
#include "common/debug.h"
#include "tss.h"
#include "common/common.h"

/**
 * Locks a mobile_image_mounter client, used for thread safety.
 *
 * @param client mobile_image_mounter client to lock
 */
static void mobile_image_mounter_lock(mobile_image_mounter_client_t client)
{
	mutex_lock(&client->mutex);
}

/**
 * Unlocks a mobile_image_mounter client, used for thread safety.
 *
 * @param client mobile_image_mounter client to unlock
 */
static void mobile_image_mounter_unlock(mobile_image_mounter_client_t client)
{
	mutex_unlock(&client->mutex);
}

/**
 * Convert a property_list_service_error_t value to a
 * mobile_image_mounter_error_t value.
 * Used internally to get correct error codes.
 *
 * @param err A property_list_service_error_t error code
 *
 * @return A matching mobile_image_mounter_error_t error code,
 *     MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR otherwise.
 */
static mobile_image_mounter_error_t mobile_image_mounter_error(property_list_service_error_t err)
{
	switch (err) {
		case PROPERTY_LIST_SERVICE_E_SUCCESS:
			return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
		case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
			return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
		case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
			return MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR;
		case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
			return MOBILE_IMAGE_MOUNTER_E_CONN_FAILED;
		default:
			break;
	}
	return MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_new(idevice_t device, lockdownd_service_descriptor_t service, mobile_image_mounter_client_t *client)
{
	property_list_service_client_t plistclient = NULL;
	mobile_image_mounter_error_t err = mobile_image_mounter_error(property_list_service_client_new(device, service, &plistclient));
	if (err != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		return err;
	}

	mobile_image_mounter_client_t client_loc = (mobile_image_mounter_client_t) malloc(sizeof(struct mobile_image_mounter_client_private));
	client_loc->parent = plistclient;

	mutex_init(&client_loc->mutex);

	*client = client_loc;
	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_start_service(idevice_t device, mobile_image_mounter_client_t * client, const char* label)
{
	mobile_image_mounter_error_t err = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
	service_client_factory_start_service(device, MOBILE_IMAGE_MOUNTER_SERVICE_NAME, (void**)client, label, SERVICE_CONSTRUCTOR(mobile_image_mounter_new), &err);
	return err;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_free(mobile_image_mounter_client_t client)
{
	if (!client)
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;

	property_list_service_client_free(client->parent);
	client->parent = NULL;
	mutex_destroy(&client->mutex);
	free(client);

	return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_lookup_image(mobile_image_mounter_client_t client, const char *image_type, plist_t *result)
{
	if (!client || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"Command", plist_new_string("LookupImage"));
	plist_dict_set_item(dict,"ImageType", plist_new_string(image_type));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

static mobile_image_mounter_error_t process_result(plist_t result, const char *expected_status)
{
	mobile_image_mounter_error_t res = MOBILE_IMAGE_MOUNTER_E_COMMAND_FAILED;
	char* strval = NULL;
	plist_t node;

	node = plist_dict_get_item(result, "Error");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &strval);
	}
	if (strval) {
		if (!strcmp(strval, "DeviceLocked")) {
			debug_info("Device is locked, can't mount");
			res = MOBILE_IMAGE_MOUNTER_E_DEVICE_LOCKED;
		} else {
			debug_info("Unhandled error '%s' received", strval);
		}
		free(strval);
		return res;
	}

	node = plist_dict_get_item(result, "Status");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &strval);
	}
	if (!strval) {
		debug_info("Error: Unexpected response received!");
	} else if (strcmp(strval, expected_status) == 0) {
		res = MOBILE_IMAGE_MOUNTER_E_SUCCESS;
	} else {
		debug_info("Error: didn't get %s but %s", expected_status, strval);
	}
	free(strval);

	return res;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_upload_image(mobile_image_mounter_client_t client, const char *image_type, size_t image_size, const char *signature, uint16_t signature_size, mobile_image_mounter_upload_cb_t upload_cb, void* userdata)
{
	if (!client || !image_type || (image_size == 0) || !upload_cb) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);
	plist_t result = NULL;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("ReceiveBytes"));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));
	plist_dict_set_item(dict, "ImageSize", plist_new_uint(image_size));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error sending XML plist to device!");
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error receiving response from device!");
		goto leave_unlock;
	}
	res = process_result(result, "ReceiveBytesAck");
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		goto leave_unlock;
	}

	size_t tx = 0;
	size_t bufsize = 65536;
	unsigned char *buf = (unsigned char*)malloc(bufsize);
	if (!buf) {
		debug_info("Out of memory");
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
	debug_info("uploading image (%d bytes)", (int)image_size);
	while (tx < image_size) {
		size_t remaining = image_size - tx;
		size_t amount = (remaining < bufsize) ? remaining : bufsize;
		ssize_t r = upload_cb(buf, amount, userdata);
		if (r < 0) {
			debug_info("upload_cb returned %d", (int)r);
			break;
		}
		uint32_t sent = 0;
		if (service_send(client->parent->parent, (const char*)buf, (uint32_t)r, &sent) != SERVICE_E_SUCCESS) {
			debug_info("service_send failed");
			break;
		}
		tx += r;
	}
	free(buf);
	if (tx < image_size) {
		debug_info("Error: failed to upload image");
		goto leave_unlock;
	}
	debug_info("image uploaded");

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("Error receiving response from device!");
		goto leave_unlock;
	}
	res = process_result(result, "Complete");

leave_unlock:
	mobile_image_mounter_unlock(client);
	if (result)
		plist_free(result);
	return res;

}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_mount_image(mobile_image_mounter_client_t client, const char *image_path, const char *signature, uint16_t signature_size, const char *image_type, plist_t *result)
{
	if (!client || !image_path || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("MountImage"));
	plist_dict_set_item(dict, "ImagePath", plist_new_string(image_path));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

static mobile_image_mounter_error_t mobile_image_mounter_query_personalization_identifiers(mobile_image_mounter_client_t client, plist_t *result)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryPersonalizationIdentifiers"));
	
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	
leave_unlock:
	return res;
}

static mobile_image_mounter_error_t mobile_image_mounter_query_nonce(mobile_image_mounter_client_t client, const char* personalized_image_type, char **nonce, uint64_t *nonce_size)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryNonce"));
	if (personalized_image_type != NULL)
		plist_dict_set_item(dict, "PersonalizedImageType", plist_new_string(personalized_image_type));
	
	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);
	
	plist_t result = NULL;
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	
	plist_t node = plist_dict_get_item(result, "PersonalizationNonce");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_get_data_val(node, nonce, nonce_size);
	} else {
		res = MOBILE_IMAGE_MOUNTER_E_MISSING_SIGNATURE;
	}
	
leave_unlock:
	if (result)
		plist_free(result);
	return res;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t get_manifest_from_tss(mobile_image_mounter_client_t client, plist_t build_manifest, uint64_t unique_chip_id, char **manifest, uint64_t *manifest_size)
{
	if (!client || !build_manifest) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t tss_request = NULL;
	
	plist_t identifiers = NULL;
	mobile_image_mounter_error_t res = mobile_image_mounter_query_personalization_identifiers(client, &identifiers);
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		goto leave_unlock;
	}
	
	plist_t personal_identifiers = plist_dict_get_item(identifiers, "PersonalizationIdentifiers");
	if (identifiers == NULL || personal_identifiers == NULL || plist_get_node_type(personal_identifiers) != PLIST_DICT) {
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
	
	tss_request = tss_request_new(NULL);
	plist_dict_iter it = NULL;
	char* key = NULL;
	plist_t subnode = NULL;
	
	plist_dict_new_iter(personal_identifiers, &it);
	if (!it) {
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
	
	do {
		plist_dict_next_item(personal_identifiers, it, &key, &subnode);
		if (!key) break;
		
		if (strncmp("Ap,", key, 3) == 0)
			plist_dict_set_item(tss_request, key, plist_copy(subnode));
		free(key);
		key = NULL;
	} while (1);
	
	free(it);
	it = NULL;
	
	// find matching build manifest entry
	uint32_t board_id = (uint32_t)_plist_dict_get_uint(personal_identifiers, "BoardId");
	uint32_t chip_id = (uint32_t)_plist_dict_get_uint(personal_identifiers, "ChipID");
	
	// Get all BuildIdentities from BuildManifest.plist
	plist_t node = plist_dict_get_item(build_manifest, "BuildIdentities");
	uint32_t num_identities = 0;
	if (node && plist_get_node_type(node) == PLIST_ARRAY)
		num_identities = plist_array_get_size(node);
	
	// Find the matching identity
	plist_t build_identity = NULL;
	for (uint64_t i = 0; i < num_identities; i++) {
		plist_t identity = plist_array_get_item(node, i);
		uint32_t cur_board_id = _plist_dict_get_uint(identity, "ApBoardID");
		uint32_t cur_chip_id = _plist_dict_get_uint(identity, "ApChipID");
		if (cur_board_id == board_id && cur_chip_id == chip_id) {
			build_identity = identity;
			break;
		}
	}
	
	if (build_identity == NULL) {
		debug_info("%s: Error finding build identity in build manifest!", __func__);
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
		
	plist_dict_set_item(tss_request, "@ApImg4Ticket", plist_new_bool(1));
	plist_dict_set_item(tss_request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(tss_request, "ApBoardID", plist_new_uint(board_id));
	plist_dict_set_item(tss_request, "ApChipID", plist_new_uint(chip_id));
	plist_dict_set_item(tss_request, "ApECID", plist_new_uint(unique_chip_id));
	plist_dict_set_item(tss_request, "ApProductionMode", plist_new_bool(1));
	plist_dict_set_item(tss_request, "ApSecurityDomain", plist_new_int(1));
	plist_dict_set_item(tss_request, "ApSecurityMode", plist_new_bool(1));
	char sep_nonce[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	plist_dict_set_item(tss_request, "SepNonce", plist_new_data(sep_nonce, 20));
	plist_dict_set_item(tss_request, "UID_MODE", plist_new_bool(0));
	 
	char *ap_nonce = NULL;
	uint64_t ap_nonce_size = 0;
	res = mobile_image_mounter_query_nonce(client, "DeveloperDiskImage", &ap_nonce, &ap_nonce_size);
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		goto leave_unlock;
	}
	
	plist_dict_set_item(tss_request, "ApNonce", plist_new_data(ap_nonce, ap_nonce_size));
	plist_mem_free(ap_nonce);
	
	// Extract more values from the build manifest
	plist_t manifest_entries = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_entries || plist_get_node_type(manifest_entries) != PLIST_DICT) {
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
	
	plist_dict_new_iter(manifest_entries, &it);
	if (!it) {
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
		goto leave_unlock;
	}
	
	plist_t parameters = plist_new_dict();
	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));
	plist_dict_set_item(parameters, "ApSecurityDomain", plist_new_int(1));
	plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
	plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
	
	do {
		plist_dict_next_item(manifest_entries, it, &key, &subnode);
		if (!key)
			break;
		
		// Only permit trusted items
		plist_t info = plist_dict_get_item(subnode, "Info");
		if (!info) continue;
		uint8_t trusted = _plist_dict_get_bool(subnode, "Trusted");
		if (!trusted) continue;
		
		plist_t tss_entry = plist_copy(subnode);
		plist_dict_remove_item(tss_entry, "Info");
		
		// Apply the restore request rules
		plist_t loadable_trust_cache = plist_dict_get_item(manifest_entries, "LoadableTrustCache");
		if (loadable_trust_cache && plist_get_node_type(loadable_trust_cache) == PLIST_DICT) {
			plist_t loadable_trust_cache_info = plist_dict_get_item(loadable_trust_cache, "Info");
			if (loadable_trust_cache_info && plist_get_node_type(loadable_trust_cache_info) == PLIST_DICT) {
				plist_t restore_request_rules = plist_dict_get_item(loadable_trust_cache, "RestoreRequestRules");
				if (restore_request_rules && plist_get_node_type(restore_request_rules) == PLIST_DICT) {
					tss_entry_apply_restore_request_rules(tss_request, parameters, restore_request_rules);
				}
			}
		}
		
		// Ensure a digest always exists
		plist_t digest = plist_dict_get_item(subnode, "Digest");
		if (!digest) {
			plist_dict_set_item(tss_entry, "Digest", plist_new_data(NULL, 0));
		}
		
		plist_dict_set_item(tss_request, key, tss_entry);
		
		free(key);
		key = NULL;
	} while (1);
	
	free(it);
	it = NULL;
	
	plist_free(parameters);
	parameters = NULL;
	
	plist_t tss_response = tss_request_send(tss_request, NULL);
	plist_t ap_img4_ticket = plist_dict_get_item(tss_response, "ApImg4Ticket");
	if (ap_img4_ticket && plist_get_node_type(ap_img4_ticket) == PLIST_DATA) {
		plist_get_data_val(ap_img4_ticket, manifest, manifest_size);
	} else {
		debug_info("%s: Error tss_response does not contain ApImg4Ticket!", __func__);
		res = MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
	}
	
	if (tss_response)
		plist_free(tss_response);
	
leave_unlock:

	if (identifiers)
		plist_free(identifiers);
	if (tss_request)
		plist_free(tss_request);
	mobile_image_mounter_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_query_personalization_manifest(mobile_image_mounter_client_t client, const char *image_type, const char *signature, uint16_t signature_size, char **manifest, uint64_t *manifest_size)
{
	if (!client || !image_type || !signature) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("QueryPersonalizationManifest"));
	plist_dict_set_item(dict, "PersonalizedImageType", plist_new_string(image_type));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	plist_t result = NULL;
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
		goto leave_unlock;
	}
	
	plist_t node = plist_dict_get_item(result, "ImageSignature");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_get_data_val(node, manifest, manifest_size);
	} else {
		res = MOBILE_IMAGE_MOUNTER_E_MISSING_SIGNATURE;
	}

leave_unlock:
	if (result)
		plist_free(result);
	mobile_image_mounter_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_mount_personalized_image(mobile_image_mounter_client_t client, const char *signature, uint16_t signature_size, const char *trustcache, uint16_t trustcache_size, const char *image_type, plist_t *result)
{
	if (!client || !trustcache || !image_type || !result) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("MountImage"));
	if (signature && signature_size != 0)
		plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));
	plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));
	if (trustcache && trustcache_size != 0)
		plist_dict_set_item(dict, "ImageTrustCache", plist_new_data(trustcache, trustcache_size));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}

LIBIMOBILEDEVICE_API mobile_image_mounter_error_t mobile_image_mounter_hangup(mobile_image_mounter_client_t client)
{
	if (!client) {
		return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
	}
	mobile_image_mounter_lock(client);

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Command", plist_new_string("Hangup"));

	mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
	plist_free(dict);

	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error sending XML plist to device!", __func__);
		goto leave_unlock;
	}

	dict = NULL;
	res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, &dict));
	if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
		debug_info("%s: Error receiving response from device!", __func__);
	}
	if (dict) {
		debug_plist(dict);
		plist_free(dict);
	}

leave_unlock:
	mobile_image_mounter_unlock(client);
	return res;
}
