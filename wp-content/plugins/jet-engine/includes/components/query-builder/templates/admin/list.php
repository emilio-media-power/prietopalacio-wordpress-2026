<div>
	<div class="cx-vui-panel jet-engine-filters-panel">
		<cx-vui-input
			:label="'<?php _e( 'Search', 'jet-engine' ); ?>'"
			:placeholder="'<?php _e( 'Enter keyword search', 'jet-engine' ); ?>'"
			:size="'fullwidth'"
			type="search"
			v-model="searchKeyword"
		></cx-vui-input>

		<cx-vui-select
			:label="'<?php _e( 'Filter by Type', 'jet-engine' ); ?>'"
			:size="'fullwidth'"
			:options-list="queryTypes"
			v-model="filterByType"
		></cx-vui-select>

		<cx-vui-select
			:label="'<?php _e( 'Sort by', 'jet-engine' ); ?>'"
			:size="'fullwidth'"
			:options-list="[
				{
					value: '',
					label: '<?php _e( 'Select...', 'jet-engine' ); ?>'
				},
				{
					value: 'title_asc',
					label: '<?php _e( 'Title: ASC', 'jet-engine' ); ?>'
				},
				{
					value: 'title_desc',
					label: '<?php _e( 'Title: DESC', 'jet-engine' ); ?>'
				},
				{
					value: 'date_asc',
					label: '<?php _e( 'Date: ASC', 'jet-engine' ); ?>'
				},
				{
					value: 'date_desc',
					label: '<?php _e( 'Date: DESC', 'jet-engine' ); ?>'
				},
			]"
			v-model="sortBy"
		></cx-vui-select>

		<cx-vui-button
			:button-style="'accent-border'"
			:size="'mini'"
			@click="resetFilters"
		>
			<span slot="label"><?php _e( 'Clear Filters', 'jet-engine' ); ?></span>
		</cx-vui-button>
	</div>

	<jet-list-navigation
		:total-items="totalItems"
		:per-page="perPage"
		:current-page="currentPage"
		@change-page="updateCurrentPage"
		@change-per-page="updatePerPage"
	></jet-list-navigation>

	<cx-vui-list-table
		:is-empty="! currentPageItems.length"
		empty-message="<?php _e( 'No queries found', 'jet-engine' ); ?>"
	>
		<cx-vui-list-table-heading
			:slots="[ 'name', 'type', 'actions' ]"
			class-name="cols-3"
			slot="heading"
		>
			<span slot="name"><?php _e( 'Name', 'jet-engine' ); ?></span>
			<span slot="type"><?php _e( 'Query Type', 'jet-engine' ); ?></span>
			<span slot="actions"><?php _e( 'Actions', 'jet-engine' ); ?></span>
		</cx-vui-list-table-heading>
		<cx-vui-list-table-item
			:slots="[ 'name', 'type', 'actions' ]"
			class-name="cols-3"
			slot="items"
			v-for="item in currentPageItems"
			:key="item.id"
		>
			<span slot="name">
				<a
					:href="getEditLink( item.id )"
					class="jet-engine-title-link"
				>{{ item.labels.name }}</a>
				<i
					v-if="item.args.description"
					class="jet-engine-description"
				>
					{{ item.args.description }}
				</i>
			</span>
			<i slot="type">{{ getQueryType( item.args.query_type ) }}</i>
			<div slot="actions" style="display: flex;">
				<a :href="getEditLink( item.id )"><?php _e( 'Edit', 'jet-engine' ); ?></a>&nbsp;|&nbsp;
				<a
					href="#"
					@click.prevent="copyItem( item )"
				><?php _e( 'Copy', 'jet-engine' ); ?></a>&nbsp;|&nbsp;
				<a
					class="jet-engine-delete-item"
					href="#"
					@click.prevent="deleteItem( item )"
				><?php _e( 'Delete', 'jet-engine' ); ?></a>
			</div>
		</cx-vui-list-table-item>
	</cx-vui-list-table>

	<jet-list-navigation
		:total-items="totalItems"
		:per-page="perPage"
		:current-page="currentPage"
		@change-page="updateCurrentPage"
		@change-per-page="updatePerPage"
	></jet-list-navigation>

	<jet-query-delete-dialog
		v-if="showDeleteDialog"
		v-model="showDeleteDialog"
		:item-id="deletedItem.id"
		:item-name="deletedItem.labels.name"
	></jet-query-delete-dialog>
</div>
