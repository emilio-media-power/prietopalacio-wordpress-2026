<div class="wrap">
    <h2><?php echo $this->plugin->displayName; ?> &raquo; <?php _e('Settings', $this->plugin->name); ?></h2>
           
    <?php    
    if (isset($this->message)) {
        ?>
        <div class="updated fade"><p><?php echo $this->message; ?></p></div>  
        <?php
    }
    if (isset($this->errorMessage)) {
        ?>
        <div class="error fade"><p><?php echo $this->errorMessage; ?></p></div>  
        <?php
    }
    ?> 
    
    <div id="poststuff">
    	<div id="post-body" class="metabox-holder columns-2">
			<!-- Content -->
			
    		<div id="post-body-content">
				<div id="normal-sortables" class="meta-box-sortables ui-sortable">                        
	                <div class="postbox">
	                    <div class="inside">
		                    <form action="options-general.php?page=<?php echo $this->plugin->name; ?>" method="post">
		                    	<p>
		                    		<label for="metricool_profile_id"><strong><?php _e('Blog or web site identifier', $this->plugin->name); ?></strong></label>
		                    		<input type="text" name="metricool_profile_id" id="metricool_profile_id" class="widefat" style="font-family:Courier New;" value="<?php echo $this->settings['metricool_profile_id']; ?>"/>
		                    		<?php _e('You can find this identifier in <a href="http://app.metricool.com/connections" target="_blank">Connections page</a> of your <a href="http://metricool.com" target="_blank">Metricool</a> account.', $this->plugin->name); ?>	
		                    	</p>
		                    	<?php wp_nonce_field($this->plugin->name, $this->plugin->name.'_nonce'); ?>
		                    	<p>
									<input name="submit" type="submit" name="Submit" class="button button-primary" value="<?php _e('Save', $this->plugin->name); ?>" /> 
								</p>
						    </form>
	                    </div>
	                </div>
	                <!-- /postbox -->
				</div>
				<!-- /normal-sortables -->
    		</div>
			<div style="text-align: center;">
				<img style="width: 100%; margin-top: -55px;" src="https://metricool.com/wp-content/uploads/wordpress-plugin-2020.png"/>
			</div>
    		<!-- /post-body-content -->
    	</div>
	</div>      
</div>
