pragma solidity 0.5.10;

library Transaction {
    
    struct RlpSlice {
        uint offset;
        uint len;
    }
    
    using Transaction for RlpSlice;

    function bytesPacked(uint n) internal pure returns (bytes memory) {
        uint i;
        for (i = 8; i <= 256; i = i + 8) {
            if (n <= 2**i)
                break;
        }
        return getBytes(bytes(abi.encodePacked(n)),32-(i/8),i/8);
    }
    
    function rlpEncodeList(bytes memory rlplist) internal pure returns (bytes memory){
        if (rlplist.length <= 0x37) {
            return bytes(abi.encodePacked(uint8(0xc0 + rlplist.length),rlplist));
        }
        bytes memory len = bytesPacked(rlplist.length);
        return bytes(abi.encodePacked(uint8(0xf7 + len.length),len,rlplist));
    }
    
    function rlpEncodeUint(uint n) internal pure returns(bytes memory) {
        if (n == 0)
            return bytesPacked(0x80);
        bytes memory nb = bytesPacked(n);
        if (n < 0x80)
            return nb;
        
        return bytes(abi.encodePacked(uint8(0x80 + nb.length), nb));
    }
    
    function copy(uint src, uint dest, uint len) internal pure {
        // Copy word-length chunks while possible
        for (; len >= 0x20; len -= 0x20) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 0x20;
            src += 0x20;
        }

        uint mask = 0x100 ** (0x20 - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }
    
    function decodeUint(bytes memory item, uint offset, uint len) internal pure returns(uint) {
        uint8 b = uint8(item[offset]);
        if (len == 1) {
            if ( b == 0x80 )
                return 0;
            else 
                return b;
        } else 
            return getUint(item,offset,len);
    }
    
    function getUint(bytes memory item, uint offset, uint len) internal pure returns (uint) {
        uint ptr;
        uint ret;
        
        if (len == 1) 
            return uint8(item[offset]);

        assembly {
            ptr := add(add(item, 0x20),offset)
            ret := div(mload(ptr), exp(0x100, sub(0x20, len)))
        }
        return ret;
    }
    
    function getBytes(bytes memory item, uint offset, uint len) internal pure returns (bytes memory) {
        bytes memory ret = new bytes(len);
        uint src;
        uint dst;
        assembly {
            src := add(add(item,0x20),offset)
            dst := add(ret,0x20)
        }
        copy(src,dst,len);
        return ret;
    }
    
    function getlen(bytes memory rlp, uint off) internal pure returns (uint encodelen, uint varlen) {
        int prefix = int(uint8(rlp[off])) - 0x80;
        
        if (prefix <= 0) {
            encodelen = 1;
            varlen = 1;
        } else {
            if ( prefix <= 0x37 ) {
                varlen = uint(prefix);
                encodelen = varlen + 1;
            } else {
                prefix = prefix - 0x37;
                varlen = getUint(rlp,off+1,uint(prefix));
                encodelen = 1 + uint(prefix) + varlen;
            }
        }
    }
    
    function getstartoffset(bytes memory rlp) internal pure returns (uint) {
        if ( uint8(rlp[0]) <= 0xf7 )
            return 1;
        return 1 + (uint8(rlp[0])-0xf7);
    }
    
    function getSlices (bytes memory rlp) internal pure returns (RlpSlice[9] memory, bytes memory ) {
        RlpSlice[9] memory slices;
        uint offset = getstartoffset(rlp);
        uint start;
        uint len;
        uint tmp;
        
        /**
         * tx.nonce start in offset and end the last byte of tx.data
         */
        start = offset;
        len = 0;
        
        for (uint i = 0; i < 9; i++) {
            (tmp,slices[i].len) = getlen(rlp,offset);
            slices[i].offset = offset + (tmp-slices[i].len);
            offset = offset + tmp;
            if (i <= 5) {
                len = len + tmp;
            }
        }
        
        return (slices,getBytes(rlp,start,len));
    }

    function getSignerAddress(bytes memory encodeData, uint chainId, uint v, uint r, uint s) internal pure returns (address) {
        bytes memory unsignedtx;
        /**
         * Not compliance with eip155 */
        if ( v == 27 || v == 28 ) 
            unsignedtx = rlpEncodeList(encodeData);
        else {
            unsignedtx = rlpEncodeList(bytes(abi.encodePacked(encodeData,rlpEncodeUint(chainId),uint16(0x8080))));
            if ( v - chainId*2 == 35 )
                v = 27;
            else
                v = 28;
        }
        return ecrecover(bytes32(keccak256(unsignedtx)),uint8(v),bytes32(r),bytes32(s));
    }

    function toUint(RlpSlice memory self, bytes memory data) internal pure returns(uint) {
        return decodeUint(data, self.offset, self. len);
    }

    function toAddress(RlpSlice memory self, bytes memory data) internal pure returns(address) {
        return address(self.toUint(data));
    }

    function toBytes(RlpSlice memory self, bytes memory data) internal pure returns(bytes memory) {
        return getBytes(data,self.offset,self.len);
    }

    function decode(bytes calldata rawTransaction, uint chainId) external pure returns (uint nonce, uint gasPrice, uint gasLimit, address to, uint value, address signer, bytes memory data) {
        RlpSlice[9] memory slices;
        bytes memory txencoded;
        uint v;
        uint r;
        uint s;

        (slices,txencoded) = getSlices(rawTransaction);

        nonce = slices[0].toUint(rawTransaction);
        gasPrice = slices[1].toUint(rawTransaction);
        gasLimit = slices[2].toUint(rawTransaction);
        to = slices[3].toAddress(rawTransaction);
        value = slices[4].toUint(rawTransaction);
        data = slices[5].toBytes(rawTransaction);

        /**
         * Get v, r and s to know the signer
         */
        v = slices[6].toUint(rawTransaction);
        r = slices[7].toUint(rawTransaction);
        s = slices[8].toUint(rawTransaction);
        signer = getSignerAddress(txencoded,chainId,v,r,s);
    }
}