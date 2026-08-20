<?php
$marker = getenv( 'LAB_MARKER' );
$form   = new Forminator_Form_Model();
$form->name     = 'OI ' . $marker;
$form->status   = 'publish';
$form->settings = array( 'formName' => 'OI ' . $marker, 'abandonment' => true );

$select               = new Forminator_Form_Field_Model();
$select->form_id      = null;
$select->slug         = 'select-1';
$select->parent_group = '';
$select->import(
	array(
		'type'       => 'select',
		'element_id' => 'select-1',
		'wrapper_id' => 'wrapper-1',
		'label'      => 'Pick',
		'options'    => array( array( 'label' => 'A', 'value' => 'a' ) ),
	)
);
$form->add_field( $select );

$form_id = $form->save();
$page_id = wp_insert_post(
	array(
		'post_type'    => 'page',
		'post_title'   => 'OI ' . $marker,
		'post_content' => '[forminator_form id="' . $form_id . '"]',
		'post_status'  => 'publish',
	)
);
echo wp_json_encode( array( 'form_id' => (int) $form_id, 'page_id' => (int) $page_id ) );
