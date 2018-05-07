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

/**
 * Implementation of the Source RCON Protocol to allow remote console commands
 * Source: https://developer.valvesoftware.com/wiki/Source_RCON_Protocol
 */
namespace pocketmine\network\rcon;

use pocketmine\command\RemoteConsoleCommandSender;
use pocketmine\event\server\RemoteServerCommandEvent;
use pocketmine\Server;
use pocketmine\utils\TextFormat;
use pocketmine\utils\Utils;

class RCON{
	/** @var Server */
	private $server;
	/** @var resource */
	private $socket;
	/** @var string */
	private $password;

	/** @var RCONInstance */
	private $instance;
	/** @var int */
	private $maxClients;

	/** @var resource */
	private $ipcMainSocket;
	/** @var resource */
	private $ipcThreadSocket;

	public function __construct(Server $server, string $password, int $port = 19132, string $interface = "0.0.0.0", int $maxClients = 50){
		$this->server = $server;
		$this->password = $password;
		$this->server->getLogger()->info("Starting remote control listener");
		if($this->password === ""){
			throw new \InvalidArgumentException("Empty password");
		}

		$this->maxClients = (int) max(1, $maxClients);
		$this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

		if($this->socket === false or !@socket_bind($this->socket, $interface, $port) or !@socket_listen($this->socket)){
			throw new \RuntimeException(trim(socket_strerror(socket_last_error())));
		}

		socket_set_block($this->socket);

		if(!@socket_create_pair(Utils::getOS() === "win" ? AF_INET : AF_UNIX, SOCK_STREAM, 0, $ipc)){
			throw new \RuntimeException(trim(socket_strerror(socket_last_error())));
		}
		[$this->ipcMainSocket, $this->ipcThreadSocket] = $ipc;

		$this->instance = new RCONInstance($this->socket, $this->password, $this->maxClients, $this->server->getLogger(), $this->ipcThreadSocket);

		socket_getsockname($this->socket, $addr, $port);
		$this->server->getLogger()->info("RCON running on $addr:$port");
	}

	public function stop(){
		$this->instance->close();

		//makes select() return on RCON thread
		@socket_close($this->ipcMainSocket);
		@socket_close($this->ipcThreadSocket);

		Server::microSleep(50000);
		$this->instance->quit();

		@socket_close($this->socket);
	}

	public function check(){
		if($this->instance->isTerminated()){
			$this->instance = new RCONInstance($this->socket, $this->password, $this->maxClients, $this->server->getLogger(), $this->ipcThreadSocket);
		}elseif($this->instance->isWaiting()){
			$response = new RemoteConsoleCommandSender();
			$command = $this->instance->cmd;

			$this->server->getPluginManager()->callEvent($ev = new RemoteServerCommandEvent($response, $command));

			if(!$ev->isCancelled()){
				$this->server->dispatchCommand($ev->getSender(), $ev->getCommand());
			}

			$this->instance->response = TextFormat::clean($response->getMessage());
			$this->instance->synchronized(function(RCONInstance $thread){
				$thread->notify();
			}, $this->instance);
		}
	}

}
