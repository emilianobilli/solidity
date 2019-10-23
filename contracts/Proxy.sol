pragma solidity 0.5.10;


contract {

    struct Account {
        uint nonce;
        uint failCount;
    }

    mapping(address => Account) accounts;
    mapping(address => bool) validPayer;
    mapping(address => bool) validDapp;

    uint public chainId;

    function getNonce (address account) external view returns (uint) {
        return accounts[account].nonce;
    }

    function addPayer(address payer) external onlyOwner {
        validPayer[payer] = true;
    }

    function removePayer(address payer) external onlyOwner {
        validPayer[payer] = false;
    }

    
    function addSender(address sender, bytes memory data) internal pure returns(bytes memory) {
        return bytes(abi.encodePacked(data,sender));
    }

    function sendRawTransction(bytes calldata rawTransaction) external {
        uint nonce;
        uint gas;
        uint gasPrice;
        uint value;
        address to;
        address from;
        bytes memory data;

        require(validPayer[msg.sender] == true, "Invalid Payer");

        (nonce,gasPrice,gas,to,value,from,data) = Transaction.decode(rawTransaction);

        require(account[from].nonce == nonce, "Invalid Nonce");

        /**
         * Chequear si la app de destino es un contrato valido
         */

        /**
         * Chequear si es un token holder
         */
        (success, ret) = address(to).call(addSender(from,data)); 

        if (success == false) {
            account[from].failCount = account[from].failCount + 1;
        }


    }

}