
EXTERN CVSetUpVMXCS:proc
EXTERN VmhostEntrydbg:proc
EXTERN CVReturnGuestRSP:proc
EXTERN CVReturnGuestRIP:proc

.data


.code

vmx_GetGdtBase PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        mov	rax, qword PTR gdtr[2]
        ret
vmx_GetGdtBase ENDP

vmx_GetIdtBase PROC
        LOCAL	idtr[10]:BYTE
        sidt	idtr
        mov		rax, qword PTR idtr[2]
        ret
vmx_GetIdtBase ENDP

vmx_GetIdtLimit PROC
        LOCAL	idtr[10]:BYTE
        sidt	idtr
        xor     rax,rax
        mov		ax, WORD PTR idtr[0]
        ret
vmx_GetIdtLimit ENDP

vmx_GetGdtLimit PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        xor     rax,rax
        mov		ax, WORD PTR gdtr[0]
        ret
vmx_GetGdtLimit ENDP

vmx_GetLdtr PROC
	    sldt	rax
	    ret
vmx_GetLdtr ENDP

vmx_vmread proc 

        mov rax,rcx
        vmread rcx,rax
        mov rax,rcx
        ret

vmx_vmread ENDP

readcs proc

     mov rax,cs
     ret

readcs endp

readds proc

     mov rax,ds
     ret

readds endp

reades proc

     mov rax,es
     ret

reades endp


readfs proc

     mov rax,fs
     ret

readfs endp

readgs proc

     mov rax,gs
     ret

readgs endp


readss proc

     mov rax,ss
     ret

readss endp

readtr proc

     str rax
     ret

readtr endp

vmx_invd proc

       invd
       ret

vmx_invd endp

vmx_wrmsr proc
        
        wrmsr
        ret

vmx_wrmsr endp

get_cpuid_info proc
        push rax
	    push rcx
	    push rdx
	    push rbx
	    push rsp     
	    push rbp
	    push rsi
	    push rdi
	    push r8
	    push r9
	    push r10
	    push r11
	    push r12
	    push r13
	    push r14
	    push r15 
        mov rax,1H
        mov rsi,rcx
        cpuid
        mov [rsi],rcx
        pop r15
	    pop r14
	    pop r13
	    pop r12
	    pop r11
	    pop r10
	    pop r9
	    pop r8
	    pop rdi
	    pop rsi
	    pop rbp
	    pop rsp
	    pop rbx
	    pop rdx
	    pop rcx
	    pop rax 
        ret

get_cpuid_info endp

set_cr4 proc
       
        mov rax,rcx
        mov rcx,cr4
        or rcx,rax
        mov cr4,rcx
        ret
set_cr4 endp

vmx_on proc

        PUSH rcx
        vmxon qword ptr [rsp]
        add rsp,8
        ret

vmx_on endp

vmxcs_clear PROC
        push rcx
        vmclear  qword ptr [rsp]
        add rsp,8
        ret

vmxcs_clear endp

VMXSaveRegState PROC
	
	pushfq	; save r/eflag

	push rax
	push rcx
	push rdx
	push rbx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	sub rsp, 0100h

	mov rcx, rsp

	call CVSetUpVMXCS;

	int 3

	jmp VMXSaveRegState
		
VMXSaveRegState ENDP

VMXRestoreRegState PROC
	add rsp, 0100h

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	pop rdx
	pop rcx
	pop rax
	
	popfq	
	ret
	
VMXRestoreRegState ENDP




vmx_vmmhostentry proc


    push r15
    mov r15,rsp
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push r15
    push rbx
    push rdx
    push rcx
    push rax
    

	mov rcx, rsp		;GuestRegs
	sub	rsp, 20h
	call VmhostEntrydbg	
	add	rsp, 20h

    cmp rax,1
    je vmxoffHandler
    

    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp,8
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    vmresume
    ret
        
vmx_vmmhostentry endp

vmxoffHandler PROC
    
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp,8
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    sub rsp, 020h       
    call CVReturnGuestRSP
    add rsp, 020h       

    mov rsp,rax 

    sub rsp, 020h       
    call CVReturnGuestRIP
    add rsp, 020h       
    
    push rax

	ret            

vmxoffHandler ENDP

vmx_vmcall PROC 
        vmcall
	    ret
vmx_vmcall ENDP

vmx_invept proc
     invept rcx,oword ptr [rdx]
     ret
vmx_invept endp

vmx_invvpid proc
    
    invvpid rcx,oword ptr [rdx]
    ret
vmx_invvpid endp

clear_cr4 proc
       
        mov rax,rcx
        mov rcx,cr4
        not rax
        and rcx,rax
        mov cr4,rcx
        ret
 
clear_cr4 endp

end
