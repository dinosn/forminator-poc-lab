<?php
$marker = getenv( 'LAB_MARKER' );
$form   = new Forminator_Form_Model();
$form->name     = 'AFU ' . $marker;
$form->status   = 'publish';
$form->settings = array( 'formName' => 'AFU ' . $marker );

$upload               = new Forminator_Form_Field_Model();
$upload->form_id      = null;
$upload->slug         = 'upload-1';
$upload->parent_group = '';
$upload->import(
	array(
		'type'          => 'upload',
		'element_id'    => 'upload-1',
		'wrapper_id'    => 'wrapper-1',
		'label'         => 'File',
		'file-type'     => 'single',
		'upload-method' => 'ajax',
	)
);
$form->add_field( $upload );

$select               = new Forminator_Form_Field_Model();
$select->form_id      = null;
$select->slug         = 'select-1';
$select->parent_group = '';
$select->import(
	array(
		'type'       => 'select',
		'element_id' => 'select-1',
		'wrapper_id' => 'wrapper-2',
		'label'      => 'Pick',
		'options'    => array( array( 'label' => 'A', 'value' => 'a' ) ),
	)
);
$form->add_field( $select );

$form_id = $form->save();
$page_id = wp_insert_post(
	array(
		'post_type'    => 'page',
		'post_title'   => 'AFU ' . $marker,
		'post_content' => '[forminator_form id="' . $form_id . '"]',
		'post_status'  => 'publish',
	)
);
echo wp_json_encode( array( 'form_id' => (int) $form_id, 'page_id' => (int) $page_id ) );
