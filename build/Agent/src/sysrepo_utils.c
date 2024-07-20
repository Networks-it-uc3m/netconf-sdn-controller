/*
 * Copyright (c) 2018 Gabriel López <gabilm@um.es>, Rafael Marín <rafa@um.es>, Fernando Pereñiguez <fernando.pereniguez@cud.upct.es> 
 *
 * This file is part of cfgipsec2.
 *
 * cfgipsec2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cfgipsec2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "sysrepo_utils.h"


pthread_mutex_t locker =PTHREAD_MUTEX_INITIALIZER;

// TODO make this as default option...
int feature_case_value = 2;

char *get_new_xpath(char * xpath) {
	
	int len = strlen(xpath)-strlen("/name");	
	char *new_xpath=malloc(len+1);
	if (!new_xpath)
		return NULL;
	for (int i = 0; i < len; ++i)
		new_xpath[i] = xpath[i];
	new_xpath[len]='\0';
	return new_xpath;
}

static int
new_entry(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val)
{
	int len = 0;
    switch(op) {
    case SR_OP_CREATED:
		len = strlen(new_val->xpath);
		const char *last_four_new = &new_val->xpath[len-4];
		if (!strcmp(last_four_new,"name")){
			return true;
		} else return false;
        break;
    case SR_OP_DELETED:
		len = strlen(old_val->xpath);
		const char *last_four_old = &old_val->xpath[len-4];
		if (!strcmp(last_four_old,"name")){
			return true;
		} else return false;
        break;
    }
	
	return true;
}






// callback for spd-entry changes
//int spd_entry_change_cb(sr_session_ctx_t *session, const char *spd_entry_xpath, sr_notif_event_t event, void *private_ctx) {

int spd_entry_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_data)
{	
	char path[512];
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
	
	(void)xpath;
	(void)request_id;
	(void)private_data;
	
	char *spd_name = NULL;
	char *new_xpath = NULL;  

	if (SR_EV_CHANGE == event) {

		DBG(" ========== SPD Changes ========== ");   

		if (xpath) {
        	sprintf(path, "%s//.", xpath);
    	} else {
        	sprintf(path, "/%s:*//.", module_name);
    	}



	    rc = sr_get_changes_iter(session, path , &it);
	    if (SR_ERR_OK != rc) {
	        ERR( "Get changes iter failed for xpath %s: %s", xpath, sr_strerror(rc));
	        goto cleanup;
	    }
	
		while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
				
			switch(oper) {
				case SR_OP_CREATED:
				
					if (new_entry(oper,old_value, new_value)) {
						spd_name = new_value->data.string_val;   
						INFO("Add spd-entry found %s ", spd_name); 
						INFO("Add spd-entry found xpath %s ", new_value->xpath); 
						
						new_xpath = get_new_xpath(new_value->xpath);	

	                	// In case 2, the SPD configuration values are applied into the kernel by means of pfkey_v2 or xfrm
	                	rc = addSPD_entry(session,it,new_xpath,spd_name,feature_case_value);
	           		 	free(new_xpath);
						if (SR_ERR_OK == rc) {
	                    	// INFO("spd-entry added ");
	               	 	}
	                	else {
							ERR("Adding spd-entry: %s",sr_strerror(rc));
	                    	sr_free_change_iter(it);
							return SR_ERR_OPERATION_FAILED;                                
	                	} 
					}
					break;
	        	case SR_OP_DELETED:                   
					if (new_entry(oper,old_value, new_value)) {
						spd_name = old_value->data.string_val;   
						INFO("Delete spd-entry found %s ", spd_name); 
						INFO("Delete spd-entry found xpath %s ", old_value->xpath); 
						
						new_xpath = get_new_xpath(old_value->xpath);
						
	                	// In case 2, the SPD configuration values are applied into the kernel by means of pfkey_v2 or xfrm
						rc = removeSPD_entry(session,it,new_xpath,spd_name,feature_case_value);
	                	free(new_xpath);
						if (SR_ERR_OK == rc) {
	                    	INFO("spd-entry deleted");
	               	 	}
	                	else {
	                    	ERR("Deleting spd-entry: %s",sr_strerror(rc));
	                    	sr_free_change_iter(it);
							return SR_ERR_OPERATION_FAILED;                             
	                	} 
					}
	        	  	break;
				case SR_OP_MODIFIED:     
		        	DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
			    	DBG("OPERATION MOVED not supported: %i",oper);
	    	} //swith               
	        sr_free_val(old_value);
	        sr_free_val(new_value);   
		}
	    DBG(" ========== END OF CHANGES =======================================");
	}
	if ((event == SR_EV_DONE) && (get_verbose_level()==CI_VERB_DEBUG)) {
	        DBG("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
	        print_current_config(session, module_name);
	}
	
cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}


int sad_entry_change_cb(sr_session_ctx_t *session,  uint32_t sub_id, const char *module_name, const char *xpath, 
	sr_event_t event, uint32_t request_id, void *private_data)
{
	char path[512];
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
	
	(void)xpath;
	(void)request_id;
	(void)private_data;
	
    char *sad_name = NULL;
	// TODO need to free this?
	char *new_xpath = NULL; 


	// pthread_mutex_lock(&sad_entry_change_lock);
	if (SR_EV_CHANGE == event) {

		DBG(" ========== SAD Changes ========== ");   
		
		if (xpath) {
        	sprintf(path, "%s//.", xpath);
    	} else {
        	sprintf(path, "/%s:*//.", module_name);
    	}

	    rc = sr_get_changes_iter(session, path , &it);
	    if (SR_ERR_OK != rc) {
	        ERR( "Get changes iter failed for xpath %s: %s", xpath, sr_strerror(rc));
	        goto cleanup;
	    }
		while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
			switch(oper) {
				case SR_OP_CREATED:
					if (new_entry(oper,old_value, new_value)) {
						sad_name = new_value->data.string_val;   
						// INFO("Add sad-entry found %s ", sad_name); 
						INFO("Add sad-entry found xpath %s ", new_value->xpath); 
					
						new_xpath = get_new_xpath(new_value->xpath);	

	                	// In case 2, the SPD configuration values are applied into the kernel by means of pfkey_v2 or xfrm
						pthread_mutex_lock(&locker);
		                rc = addSAD_entry(session,it,new_xpath,sad_name);
						pthread_mutex_unlock(&locker);
						if (SR_ERR_OK == rc) {
	                    	// DBG("sad-entry ");
	               	 	}
	                	else {
							ERR("Adding sad-entry: %s",sr_strerror(rc));
	                    	sr_free_change_iter(it);
							// pthread_mutex_unlock(&sad_entry_change_lock);
							return SR_ERR_OPERATION_FAILED;                                
	                	} 
					}
					break;
	        	case SR_OP_DELETED:                   
					if (new_entry(oper,old_value, new_value)) {
						sad_name = old_value->data.string_val;   
						// INFO("Delete sad-entry found %s ", sad_name); 
						INFO("Delete sad-entry found xpath %s ", old_value->xpath); 
						new_xpath = get_new_xpath(old_value->xpath);
	                	// In case 2, the SPD configuration values are applied into the kernel by means of pfkey_v2 or xfrm
						rc = removeSAD_entry(session,it,new_xpath,sad_name);
						if (SR_ERR_OK == rc) {
	                    	INFO("sad-entry deleted");
	               	 	}
	                	else {
	                    	ERR("Deleting sad-entry: %s",sr_strerror(rc));
	                    	sr_free_change_iter(it);
							return SR_ERR_OPERATION_FAILED;                             
	                	} 
					}
	        	  	break;
				case SR_OP_MODIFIED:     
		        	DBG("OPERATION MODIFIED not supported: %i",oper);
				case SR_OP_MOVED:     
			    	DBG("OPERATION MOVED not supported: %i",oper);
	    	} //swith                
	        sr_free_val(old_value);
	        sr_free_val(new_value);   
		}
	    DBG(" ========== END OF CHANGES =======================================");
	}
	if ((event == SR_EV_DONE) && (get_verbose_level()==CI_VERB_DEBUG)) {
	        printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
	        print_current_config(session, module_name);
	}
	
cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;	
}


// callbackk for sad_register mmessages
int sadb_register(sr_session_ctx_t *session) {
    //INFO("SADB REGISTER RECEIVED")
    if (pf_exec_register(session, SADB_SATYPE_ESP)) {
        ERR("sadb_register in exec_register: %s",sr_strerror(SR_ERR_INTERNAL));
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}


int exit_verification = 0;
#ifdef Enarx
int sad_verification_process() {
	// TODO perform also verifications after installing new entries. 
	while(exit_verification == 0) {
		// DBG("====== Starting sad_entries verification process ======");
		verify_sad_nodes();
		// manage verification process every 10 seconds
		sleep(5);
	}

}
int close_verification_process() {
	exit_verification = 1;
}
#endif 