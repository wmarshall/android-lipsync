package org.mort11.lipsync;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.mort11.lipsync.error.AuthError;
import org.mort11.lipsync.error.HUPError;
import org.mort11.lipsync.error.LipSyncError;
import org.mort11.lipsync.error.TerminatedError;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

public abstract class LipSyncBase {
	private Cipher AESEncoder;
	private Cipher AESDecoder;
	private SQLiteDatabase conn;

	public final String LogCatTag = "LipSync";

	public final String VERSION = "1.0";
	public final String CIPHERMODE = "AES/CTR/NoPadding";
	public final String CONTINUE = "LipSync_Continue";
	public final String DONE = "LipSync_Done";
	public final char ETB = 0x17;
	public final int TIMEOUT = 30;

	private int totalBytes = 0;
	private long time;
	private byte[] key;
	private byte[] iv;
	final String LOCAL_ID_COL_NAME = "_rowid_";
	final String UUID_COL_NAME = "_lipsync_uuid";

	public LipSyncBase(SQLiteDatabase connection, String secret) {
		conn = connection;
		MessageDigest sha256;

		try {
			sha256 = MessageDigest.getInstance("SHA-256");
			Log.d(LogCatTag, "Initializing with secret = " + secret);
			sha256.update(secret.getBytes("UTF-8"));
			key = sha256.digest();
			iv = new byte[16];
			for (int i = 0; i < 8; i++) {
				iv[i] = key[key.length - 8 + i];
			}
			Log.d(LogCatTag, "Key = " + toHex(key));
			Log.d(LogCatTag, "IV = " + toHex(iv));
			AESEncoder = Cipher.getInstance(CIPHERMODE);
			AESEncoder.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
					new IvParameterSpec(iv));
			AESDecoder = Cipher.getInstance(CIPHERMODE);
			AESDecoder.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
					new IvParameterSpec(iv.clone()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

	private boolean auth_valid(JSONObject auth) throws JSONException {
		return auth.getString("LipSync_Version").equals(VERSION)
				&& auth.getString("LipSync_Digest").equals(toHex(key));
	}

	protected JSONObject check_terminated(JSONObject message)
			throws TerminatedError {
		try {
			if (!message.getBoolean(CONTINUE)) {
				Log.d(LogCatTag, "Other side terminated");
				throw new TerminatedError();
			}
		} catch (JSONException e) {
		}
		return message;
	}

	private JSONObject create_auth_message() throws JSONException {

		return new JSONObject().put("LipSync_Version", VERSION).put(
				"LipSync_Digest", toHex(key));
	}

	private String toHex(byte[] in) {
		String processed = "";
		for (int i = 0; i < in.length; i++) {
			int next = in[i];
			String hex = Integer.toHexString(next & 0xff);
			if (hex.length() == 1) {
				processed += "0";
			}
			processed += hex;
		}
		return processed;
	}

	private JSONObject create_continue_message(boolean cont)
			throws JSONException {
		return new JSONObject().put(CONTINUE, cont);
	}

	private JSONObject create_status_message(String table) throws JSONException {
		return new JSONObject().put("table", table).put("uuids",
				new JSONArray(get_uuid_map(table)));
	}

	private void do_auth(Socket sock) throws JSONException, LipSyncError,
			IllegalBlockSizeException, BadPaddingException, IOException {
		send_auth_message(sock);
		Log.d(LogCatTag, "Sent Auth Message");
		process_auth_message(sock);
		Log.d(LogCatTag, "Got Auth Message");
		send_auth_response(sock, true);
		process_auth_response(sock);
	}

	private ArrayList<String> do_request(Socket sock,
			ArrayList<String> needed_records) throws JSONException,
			LipSyncError, IllegalBlockSizeException, BadPaddingException,
			IOException {
		send_request_message(sock, needed_records);
		ArrayList<String> need_to_send = process_request_message(sock);
		Log.d(LogCatTag, "Need to Send: " + need_to_send.toString());
		return need_to_send;
	}

	private void do_response(Socket sock, String table,
			ArrayList<String> needed_records, ArrayList<String> need_to_send)
			throws TerminatedError, LipSyncError, JSONException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		send_response_messages(sock, table, need_to_send);
		process_response(sock, table, needed_records);
	}

	protected abstract TableAndNeededRecords do_status(Socket sock, String table)
			throws IllegalBlockSizeException, BadPaddingException, IOException,
			JSONException, TerminatedError, LipSyncError;

	private ArrayList<String> get_col_map(String table) {
		return get_col_map(table, true);
	}

	private ArrayList<String> get_col_map(String table, boolean omit_local) {
		Log.d(LogCatTag, table);
		// conn.query(table, null, null, null, null, null, null);
		ArrayList<String> names = new ArrayList<String>(Arrays.asList(conn
				.query(table, null, null, null, null, null, null)
				.getColumnNames()));
		Log.d(LogCatTag, names.toString());
		if (omit_local)
			names.remove(LOCAL_ID_COL_NAME);
		return names;
	}

	private byte[] get_block(Socket sock) throws IOException {
		byte[] buffer = new byte[AESDecoder.getBlockSize()];
		int offset = 0;
		int tries = 0;
		while (offset < AESDecoder.getBlockSize()) {
			try {
				int lenrx = sock.getInputStream().read(buffer, offset,
						buffer.length - (offset));
				if (lenrx < 0) {
					throw new IOException();
				} else {
					offset += lenrx;
					totalBytes += lenrx;
				}
				Log.d(LogCatTag, "OFFSET = " + offset);
				Log.d(LogCatTag, "Rx = " + totalBytes);
			} catch (IOException e) {
				if (tries++ > 4) {
					throw e;
				}
				Log.d(LogCatTag, "RETRY");
			}
		}
		return buffer;
	}

	protected Object get_message(Socket sock) throws LipSyncError,
			JSONException {
		String plaintext = "";
		time = System.currentTimeMillis();
		while (true) {
			try {
				byte[] block = new byte[AESDecoder.getBlockSize()];
				block = get_block(sock);
				plaintext += new String(AESDecoder.update(block), "UTF-8");
				Log.d(LogCatTag, "ELAPSED = "
						+ (System.currentTimeMillis() - time));
				if (plaintext.endsWith(String.valueOf(ETB))) {
					totalBytes = 0;
					break;
				}
			} catch (IOException e) {
				e.printStackTrace();
				throw new HUPError();
			}
		}
		Log.d(LogCatTag, "Got message |" + plaintext + "|");
		return new JSONTokener(plaintext.substring(0, plaintext.length() - 1))
				.nextValue();
	}

	protected ArrayList<String> get_uuid_map(String table) {
		Cursor cur = conn.query(table, new String[] { UUID_COL_NAME }, null,
				null, null, null, null);
		ArrayList<String> uuids = new ArrayList<String>();
		cur.moveToFirst();
		while (!cur.isAfterLast()) {
			uuids.add(cur.getString(0));
			cur.moveToNext();
		}
		return uuids;
	}

	private void init_table(String table) {
		conn.beginTransaction();
		try {

			ArrayList<String> cols = get_col_map(table, false);
			if (!cols.contains(UUID_COL_NAME)) {
				Log.d(LogCatTag, "ADDING COL");
				conn.execSQL("ALTER TABLE " + table + " ADD COLUMN "
						+ UUID_COL_NAME + " TEXT");
			}
			conn.setTransactionSuccessful();
			Log.d(LogCatTag, "Successfully initialized table");
		} finally {
			conn.endTransaction();
			Log.d(LogCatTag, get_col_map(table, false).toString());
		}
	}

	private void process_auth_message(Socket sock) throws JSONException,
			LipSyncError {
		if (!auth_valid((JSONObject) get_message(sock))) {
			throw new AuthError();
		}

	}

	private void process_auth_response(Socket sock) throws AuthError,
			JSONException {
		try {
			check_terminated((JSONObject) get_message(sock));
		} catch (LipSyncError e) {
			throw new AuthError();
		}
	}

	private ArrayList<String> process_request_message(Socket sock)
			throws JSONException, LipSyncError {
		JSONArray partner_needs = ((JSONObject) get_message(sock))
				.getJSONArray("need");
		ArrayList<String> uuids = new ArrayList<String>();
		for (int i = 0; i < partner_needs.length(); i++) {
			uuids.add(partner_needs.getString(i));
		}
		return uuids;
	}

	private void process_response(Socket sock, String table,
			ArrayList<String> needed_records) throws TerminatedError,
			LipSyncError, JSONException {

		while (true) {
			JSONObject message = check_terminated((JSONObject) get_message(sock));
			try {
				message.getBoolean(DONE);
				Log.d(LogCatTag, "Other side done sending");
				break;
			} catch (JSONException e) {
			}
			if (needed_records.indexOf(message.get("uuid")) == -1) {
				continue;
			}
			ContentValues cv = new ContentValues();
			JSONObject record = message.getJSONObject("record");
			for (int i = 0; i < record.length(); i++) {
				cv.put(record.names().getString(i),
						record.getString(record.names().getString(i)));
			}
			conn.insert(table, null, cv);
		}
	}

	protected TableAndNeededRecords process_status_message(Socket sock)
			throws TerminatedError, LipSyncError, JSONException {
		return process_status_message(sock, null);
	}

	protected abstract TableAndNeededRecords process_status_message(
			Socket sock, String table) throws TerminatedError, LipSyncError,
			JSONException;

	private void send_auth_message(Socket sock) throws JSONException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		send_message(sock, create_auth_message().toString());
	}

	private void send_auth_response(Socket sock, boolean status)
			throws JSONException, IllegalBlockSizeException,
			BadPaddingException, IOException {
		send_message(sock, create_continue_message(status).toString());
	}

	private void send_message(Socket sock, String message)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		while (((message.length() + 1) % AESEncoder.getBlockSize()) != 0) {
			message += " ";
		}
		message += ETB;
		Log.d(LogCatTag, "Sending message |" + message + "|");
		sock.getOutputStream().write(
				AESEncoder.update(message.getBytes("UTF-8")));
	}

	private void send_request_message(Socket sock,
			ArrayList<String> needed_records) throws IllegalBlockSizeException,
			BadPaddingException, IOException, JSONException {
		JSONArray need = new JSONArray();
		for (String record : needed_records) {
			need.put(record);
		}
		Log.d(LogCatTag, "Need: " + need.toString());
		send_message(sock, new JSONObject().put("need", need).toString());
	}

	private void send_response_messages(Socket sock, String table,
			ArrayList<String> need_to_send) throws JSONException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		ArrayList<String> cols = get_col_map(table);
		if (!cols.contains(UUID_COL_NAME)) {
			cols.add(UUID_COL_NAME);
		}
		String[] colsarray = new String[cols.size()];
		for (int i = 0; i < cols.size(); i++) {
			colsarray[i] = cols.get(i);
		}
		for (String uuid : need_to_send) {
			Cursor cur = conn.query(table, colsarray, UUID_COL_NAME + " = ?",
					new String[] { uuid }, null, null, null);
			cur.moveToFirst();
			JSONObject message = new JSONObject().put("uuid", uuid);
			JSONObject record = new JSONObject();
			for (int i = 0; i < colsarray.length; i++) {
				record.put(colsarray[i],
						cur.getString(cur.getColumnIndex(colsarray[i])));
			}
			message.put("record", record);
			send_message(sock, message.toString());
		}
		send_message(sock, new JSONObject().put(DONE, true).toString());

	}

	protected void send_status_message(Socket sock, String table)
			throws IllegalBlockSizeException, BadPaddingException, IOException,
			JSONException {
		send_message(sock, create_status_message(table).toString());
	}

	public void sync(Socket sock) throws IOException,
			IllegalBlockSizeException, BadPaddingException, JSONException,
			LipSyncError {
		sync(sock, null);
	}

	private void reset_crypto() {
		try {
			AESEncoder.doFinal();
			AESDecoder.doFinal();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	public void sync(Socket sock, String table) throws IOException,
			IllegalBlockSizeException, BadPaddingException, JSONException,
			LipSyncError {
		sock.setSoTimeout(TIMEOUT * 1000);
		time = System.currentTimeMillis();
		try {
			do_auth(sock);
			TableAndNeededRecords tnr = do_status(sock, table);
			ArrayList<String> need_to_send = do_request(sock,
					tnr.needed_records);
			do_response(sock, tnr.table, tnr.needed_records, need_to_send);
		} finally {
			try {
				terminate(sock);
				if (conn.inTransaction()) {
					conn.endTransaction();
				}
				reset_crypto();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (JSONException e) {
				e.printStackTrace();
			}
			sock.close();
		}

	}

	private void terminate(Socket sock) throws IllegalBlockSizeException,
			BadPaddingException, IOException, JSONException {
		send_message(sock, create_continue_message(false).toString());
		JSONObject message = new JSONObject();
		while ((message.length() == 0) || (message.getBoolean(CONTINUE))) {
			try {
				message = (JSONObject) get_message(sock);
			} catch (LipSyncError e) {
				break;
			}
		}
	}

	protected void update_table(String table) {
		init_table(table);
		Cursor cur = conn.query(table, new String[] { LOCAL_ID_COL_NAME },
				UUID_COL_NAME + " IS NULL", null, null, null, null);
		cur.moveToFirst();
		while (!cur.isAfterLast()) {
			ContentValues cv = new ContentValues();
			cv.put(UUID_COL_NAME, UUID.randomUUID().toString());
			conn.update(table, cv, LOCAL_ID_COL_NAME + " = ?",
					new String[] { cur.getString(0) });
			cur.moveToNext();
		}
	}
}
