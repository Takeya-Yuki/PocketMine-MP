<?php

/*
 *
 *  ____            _        _   __  __ _                  __  __ ____
 * |  _ \ ___   ___| | _____| |_|  \/  (_)_ __   ___      |  \/  |  _ \
 * | |_) / _ \ / __| |/ / _ \ __| |\/| | | '_ \ / _ \_____| |\/| | |_) |
 * |  __/ (_) | (__|   <  __/ |_| |  | | | | | |  __/_____| |  | |  __/
 * |_|   \___/ \___|_|\_\___|\__|_|  |_|_|_| |_|\___|     |_|  |_|_|
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @author PocketMine Team
 * @link http://www.pocketmine.net/
 *
 *
*/

declare(strict_types=1);

namespace pocketmine\network\rcon;

use pocketmine\Thread;
use pocketmine\utils\Binary;

class RCONInstance extends Thread{
	private const STATUS_DISCONNECTED = -1;
	private const STATUS_AUTHENTICATING = 0;
	private const STATUS_CONNECTED = 1;

	/** @var string */
	public $cmd;
	/** @var string */
	public $response;

	/** @var bool */
	private $stop;
	/** @var resource */
	private $socket;
	/** @var string */
	private $password;
	/** @var int */
	private $maxClients;
	/** @var bool */
	private $waiting;
	/** @var \ThreadedLogger */
	private $logger;

	public function isWaiting(){
		return $this->waiting;
	}

	/**
	 * @param resource        $socket
	 * @param string          $password
	 * @param int             $maxClients
	 * @param \ThreadedLogger $logger
	 */
	public function __construct($socket, string $password, int $maxClients = 50, \ThreadedLogger $logger){
		$this->stop = false;
		$this->cmd = "";
		$this->response = "";
		$this->socket = $socket;
		$this->password = $password;
		$this->maxClients = $maxClients;
		$this->logger = $logger;

		$this->start(PTHREADS_INHERIT_NONE);
	}

	private function writePacket($client, $requestID, $packetType, $payload){
		$pk = Binary::writeLInt((int) $requestID)
			. Binary::writeLInt((int) $packetType)
			. $payload
			. "\x00\x00"; //Terminate payload and packet
		return socket_write($client, Binary::writeLInt(strlen($pk)) . $pk);
	}

	private function readPacket($client, &$requestID, &$packetType, &$payload){
		$d = socket_read($client, 4);
		if($this->stop){
			return false;
		}elseif($d === false){
			return null;
		}elseif($d === "" or strlen($d) < 4){
			return false;
		}

		$size = Binary::readLInt($d);
		if($size < 0 or $size > 65535){
			return false;
		}
		$requestID = Binary::readLInt(socket_read($client, 4));
		$packetType = Binary::readLInt(socket_read($client, 4));
		$payload = rtrim(socket_read($client, $size + 2)); //Strip two null bytes
		return true;
	}

	public function close(){
		$this->stop = true;
	}

	public function run(){
		$this->registerClassLoader();

		/** @var resource[] $clients */
		$clients = [];
		/** @var int[] $statuses */
		$statuses = [];
		/** @var float[] $timeouts */
		$timeouts = [];

		/** @var int $nextClientId */
		$nextClientId = 0;

		while(!$this->stop){
			$r = $clients;
			$r["main"] = $this->socket; //this is ugly, but we need to be able to mass-select()
			$w = null;
			$e = null;

			$dead = $clients;

			if(socket_select($r, $w, $e, 0, 200000) > 0){
				foreach($r as $id => $sock){
					unset($dead[$id]);
					if($sock === $this->socket){
						if(($client = socket_accept($this->socket)) !== false){
							if(count($clients) >= $this->maxClients){
								@socket_close($client);
							}else{
								socket_set_block($client);
								socket_set_option($client, SOL_SOCKET, SO_KEEPALIVE, 1);

								$id = $nextClientId++;
								$clients[$id] = $client;
								$statuses[$id] = self::STATUS_AUTHENTICATING;
								$timeouts[$id] = microtime(true) + 5;
							}
						}
					}else{
						$p = $this->readPacket($sock, $requestID, $packetType, $payload);
						if($p === false){
							$statuses[$id] = self::STATUS_DISCONNECTED;
							continue;
						}elseif($p === null){
							continue;
						}

						switch($packetType){
							case 3: //Login
								if($statuses[$id] !== self::STATUS_AUTHENTICATING){
									$statuses[$id] = self::STATUS_DISCONNECTED;
									break;
								}
								if($payload === $this->password){
									socket_getpeername($sock, $addr, $port);
									$this->logger->info("Successful Rcon connection from: /$addr:$port");
									$this->writePacket($sock, $requestID, 2, "");
									$statuses[$id] = self::STATUS_CONNECTED;
								}else{
									$statuses[$id] = self::STATUS_DISCONNECTED;
									$this->writePacket($sock, -1, 2, "");
								}
								break;
							case 2: //Command
								if($statuses[$id] !== self::STATUS_CONNECTED){
									$statuses[$id] = self::STATUS_DISCONNECTED;
									break;
								}
								if(strlen($payload) > 0){
									$this->cmd = ltrim($payload);
									$this->synchronized(function(){
										$this->waiting = true;
										$this->wait();
									});
									$this->waiting = false;
									$this->writePacket($sock, $requestID, 0, str_replace("\n", "\r\n", trim($this->response)));
									$this->response = "";
									$this->cmd = "";
								}
								break;
						}
					}
				}
			}

			foreach($dead as $id => $client){
				if($statuses[$id] !== self::STATUS_DISCONNECTED and !$this->stop){
					if($statuses[$id] === self::STATUS_AUTHENTICATING and $timeouts[$id] < microtime(true)){ //Timeout
						$statuses[$id] = self::STATUS_DISCONNECTED;
						continue;
					}
				}else{
					@socket_set_option($client, SOL_SOCKET, SO_LINGER, ["l_onoff" => 1, "l_linger" => 1]);
					@socket_shutdown($client, 2);
					@socket_set_block($client);
					@socket_read($client, 1);
					@socket_close($client);

					unset($clients[$id], $statuses[$id], $timeouts[$id]);
				}
			}
		}
	}

	public function getThreadName() : string{
		return "RCON";
	}
}
