<?php
/**
 * Lab-only helpers. This file is copied into the isolated Docker image and is
 * inert unless FORMINATOR_LAB=1 is set by docker-compose.yml.
 */

if ( '1' !== getenv( 'FORMINATOR_LAB' ) ) {
	return;
}

// Required configuration precondition for the abandoned-form test cases.
add_filter( 'forminator_form_abandonment_disabled', '__return_false' );

/**
 * Benign public-property object-injection canary for the XML-RPC transport.
 * It proves magic-method execution only; it is not evidence of a production
 * gadget. The generated marker endpoint removes itself after one request.
 */
class Lab_OI_PubProp_Canary {
	public $marker = '';
	public $path   = '';

	public function __wakeup() {
		$marker = preg_replace( '/[^A-Za-z0-9_-]/', '', (string) $this->marker );
		if ( '' === $marker ) {
			return;
		}

		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['error'] ) ) {
			return;
		}

		$file    = trailingslashit( $uploads['basedir'] ) . 'lab-oi-pubprop-' . $marker . '.php';
		$payload = '<?php header(\'Content-Type: text/plain\'); echo '
			. var_export( 'CANARY:' . $marker, true )
			. '; @unlink(__FILE__);';
		file_put_contents( $file, $payload, LOCK_EX );
	}
}

/**
 * Deterministic nonce minting for authenticated lab setup and reader triggers.
 * The Docker port is loopback-only and the fixed key is intentionally lab-only.
 */
add_action(
	'init',
	static function () {
		if ( empty( $_GET['__labnonce'] ) ) {
			return;
		}

		$key      = isset( $_GET['labkey'] ) ? (string) wp_unslash( $_GET['labkey'] ) : '';
		$expected = (string) getenv( 'FORMINATOR_LAB_NONCE_KEY' );
		if ( ! is_user_logged_in() || '' === $expected || ! hash_equals( $expected, $key ) ) {
			wp_send_json_error( array( 'error' => 'forbidden' ), 403 );
		}

		$actions = isset( $_GET['actions'] ) ? explode( ',', (string) wp_unslash( $_GET['actions'] ) ) : array();
		$result  = array();
		foreach ( $actions as $action ) {
			$action = preg_replace( '/[^A-Za-z0-9_-]/', '', $action );
			if ( '' !== $action ) {
				$result[ $action ] = wp_create_nonce( $action );
			}
		}
		wp_send_json( $result );
	},
	0
);
