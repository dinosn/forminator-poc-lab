<?php
$marker  = getenv( 'LAB_MARKER' );
$poll_id = wp_insert_post(
	array(
		'post_type'   => 'forminator_polls',
		'post_status' => 'publish',
		'post_title'  => 'Poll ' . $marker,
	)
);
update_post_meta(
	$poll_id,
	'forminator_form_meta',
	array(
		'settings' => array(
			'poll-title'       => 'Poll ' . $marker,
			'poll-description' => 'Local validation lab',
			'results-style'    => 'bar',
			'enable-results'   => 'true',
		),
		'fields'   => array(
			array( 'id' => 'answer-1', 'element_id' => 'answer-1', 'title' => 'ALPHA', 'type' => 'answer', 'color' => '#51cfd2', 'wrapper_id' => 'wrapper-1' ),
			array( 'id' => 'answer-2', 'element_id' => 'answer-2', 'title' => 'BETA', 'type' => 'answer', 'color' => '#56d28c', 'wrapper_id' => 'wrapper-2' ),
		),
	)
);
$page_id = wp_insert_post(
	array(
		'post_type'    => 'page',
		'post_status'  => 'publish',
		'post_title'   => 'Poll ' . $marker,
		'post_content' => '[forminator_poll id="' . $poll_id . '"]',
	)
);
echo wp_json_encode( array( 'poll_id' => (int) $poll_id, 'page_id' => (int) $page_id ) );
