/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package honeypot;

public class PcapException extends Exception {

	private static final long serialVersionUID = -6154403878400623927L;

	public PcapException(String message) {
        super(message);
    }
}