use {
    anchor_lang::prelude::*,
    anchor_spl::{
        metadata::{create_metadata_accounts_v3, CreateMetadataAccountsV3, Metadata},
        associated_token::AssociatedToken,
        token::{mint_to, Token, TokenAccount, Mint, MintTo},
    },
    mpl_token_metadata::{pda::find_metadata_account, state::DataV2},
};
use anchor_lang::solana_program::sysvar::instructions as instructions_sysvar_module;
use std::mem::size_of;
use anchor_lang::solana_program::ed25519_program::ID as ED25519_PROGRAM_ID;
use solana_program::system_instruction;

declare_id!("CirPUNCW9i2FuVQ5hPHbPiUmk5B3sgTSbvJ6roaVg1M1");

const EXPECTED_PUBLIC_KEY_OFFSET: usize = 16;
const EXPECTED_PUBLIC_KEY_RANGE: std::ops::Range<usize> =
    EXPECTED_PUBLIC_KEY_OFFSET..(EXPECTED_PUBLIC_KEY_OFFSET + 32);

#[program]
pub mod meme_nft {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        owner: Pubkey,
        receive_address: Pubkey,
        s_nft_price: u64,
    ) -> Result<()> {
        let global_state = &mut ctx.accounts.global_state;
        global_state.owner = owner;
        global_state.receive_address = receive_address;
        global_state.s_nft_price = s_nft_price;
        Ok(())
    }

    pub fn update_global_state(
        ctx: Context<UpdateGlobalState>,
        owner: Pubkey,
        receive_address: Pubkey,
        s_nft_price: u64,
    ) -> Result<()> {
        if ctx.accounts.payer.key() != ctx.accounts.global_state.owner {
            return err!(ErrorCode::ConstraintExecutable);
        }
        let global_state = &mut ctx.accounts.global_state;
        global_state.owner = owner;
        global_state.receive_address = receive_address;
        global_state.s_nft_price = s_nft_price;
        Ok(()) 
    }

    pub fn create_nft(
        ctx: Context<CreateNFT>, 
        ix_args: CreateNFTArgs,
    ) -> Result<()> {
        let payer = ctx.accounts.payer.key();
        if payer != ctx.accounts.global_state.owner {
            return err!(ErrorCode::ConstraintSigner);
        }
        let seeds = "mint_".to_string() + &ix_args.nft_name;
        let signer_seeds: &[&[&[u8]]] = &[&[seeds.as_ref(), &[*ctx.bumps.get("mint_account").unwrap()]]];
        // Cross Program Invocation (CPI) signed by PDA
        // Invoking the create_metadata_account_v3 instruction on the token metadata program
        create_metadata_accounts_v3(
            CpiContext::new(
                ctx.accounts.token_metadata_program.to_account_info(),
                CreateMetadataAccountsV3 {
                    metadata: ctx.accounts.metadata_account.to_account_info(),
                    mint: ctx.accounts.mint_account.to_account_info(),
                    mint_authority: ctx.accounts.mint_account.to_account_info(), // PDA is mint authority
                    update_authority: ctx.accounts.mint_account.to_account_info(), // PDA is update authority
                    payer: ctx.accounts.payer.to_account_info(),
                    system_program: ctx.accounts.system_program.to_account_info(),
                    rent: ctx.accounts.rent.to_account_info(),
                },
            )
            .with_signer(signer_seeds),
            DataV2 {
                name: ix_args.nft_name.clone(),
                symbol: ix_args.nft_symbol.clone(),
                uri: ix_args.nft_uri.clone(),
                seller_fee_basis_points: 0,
                creators: None,
                collection: None,
                uses: None,
            },
            false, // Is mutable
            true,  // Update authority is signer
            None,  // Collection details
        )?;
        let event = CreateNFTEvent{
            nft_name: ix_args.nft_name.clone(),
            nft_symbol: ix_args.nft_symbol.clone(),
            nft_uri: ix_args.nft_uri.clone(),
        };
        emit!(event);
        msg!("{:?}", event);
        msg!("Token created successfully.");
        Ok(())
    }

    pub fn receive_nft_fragment(
        ctx: Context<ReceiveNFTFragment>,
        ix_args: ReceiveNFTArgs,
    ) -> Result<()> {
        msg!("GlobalState Owner: {}", ctx.accounts.global_state.owner);
        // verify
        let ix = instructions_sysvar_module::get_instruction_relative(
            -1,
            &ctx.accounts.instructions_sysvar,
        )?;
        if !validate_ed25519_ix(&ix) {
            return err!(ErrorCode::InstructionMissing);
        }
        let pub_key: Pubkey = Pubkey::new(&ix.data[EXPECTED_PUBLIC_KEY_RANGE]);
        msg!("signature acccount key {}", pub_key);

        if pub_key != ctx.accounts.global_state.owner {
            return err!(ErrorCode::ConstraintSigner);
        }
        let nonce_data = &ix.data[112..];
        match ClaimNFT::try_from_slice(&nonce_data.to_vec()) {
            Ok(claim_nonce) => {
                if claim_nonce.event_type != "receive_nft_fragment" {
                    return err!(ErrorCode::ConstraintSigner);
                }
                if claim_nonce.customer != ctx.accounts.payer.key() {
                    return err!(ErrorCode::ConstraintSigner);
                }
                if claim_nonce.nonce != ix_args.nonce {
                    msg!("args nonce: {}", ix_args.nonce);
                    msg!("sign nonce: {}", claim_nonce.nonce);
                    return err!(ErrorCode::ConstraintExecutable);
                }
                let event = NFTFragmentEvent{
                    user: ctx.accounts.payer.key(),
                    nonce: claim_nonce.nonce,
                    nft_name: claim_nonce.nft_name,
                    nft_metadata: claim_nonce.nft_metadata,
                    amount: claim_nonce.amount,
                };
                emit!(event);
                msg!("{:?}", event);
                let claim_account = &mut ctx.accounts.claim_account;
                claim_account.nonce = claim_nonce.nonce;
                claim_account.user = claim_nonce.customer;
            },
            Err(_) => return err!(ErrorCode::InstructionMissing),
        };
        Ok(())
    }

    pub fn synthesis_nft(
        ctx: Context<SynthesisNFT>,
        ix_args: SynthesisNFTArgs,
    ) -> Result<()> {
        msg!("GlobalState Owner: {}", ctx.accounts.global_state.owner);
        // verify
        let ix = instructions_sysvar_module::get_instruction_relative(
            -1,
            &ctx.accounts.instructions_sysvar,
        )?;
        if !validate_ed25519_ix(&ix) {
            return err!(ErrorCode::InstructionMissing);
        }
        let pub_key: Pubkey = Pubkey::new(&ix.data[EXPECTED_PUBLIC_KEY_RANGE]);
        msg!("signature acccount key {}", pub_key);

        if pub_key != ctx.accounts.global_state.owner {
            return err!(ErrorCode::ConstraintSigner);
        }
        let nonce_data = &ix.data[112..];
        match ClaimNFT::try_from_slice(&nonce_data.to_vec()) {
            Ok(claim_nonce) => {
                if claim_nonce.event_type != "synthesis_nft" && claim_nonce.event_type != "mint_nft" {
                    return err!(ErrorCode::ConstraintSigner);
                }
                if claim_nonce.customer != ctx.accounts.payer.key() {
                    return err!(ErrorCode::ConstraintSigner);
                }
                if claim_nonce.nonce != ix_args.nonce {
                    msg!("args nonce: {}", ix_args.nonce);
                    msg!("sign nonce: {}", claim_nonce.nonce);
                    return err!(ErrorCode::ConstraintExecutable);
                }
                if claim_nonce.nft_name != ix_args.nft_name {
                    msg!("Nft name: {}", claim_nonce.nft_name);
                    return err!(ErrorCode::ConstraintExecutable);
                }
                if claim_nonce.nft_type != ix_args.nft_type {
                    msg!("Nft type: {}", claim_nonce.nft_type);
                    return err!(ErrorCode::ConstraintExecutable);
                }
                let claim_account = &mut ctx.accounts.claim_account;
                claim_account.nonce = claim_nonce.nonce;
                claim_account.user = claim_nonce.customer;
            },
            Err(_) => return err!(ErrorCode::InstructionMissing),
        };
        if ix_args.nft_type == "super" {
            let from_account = &ctx.accounts.payer;
            let to_account = &ctx.accounts.to;
            if ctx.accounts.to.key() != ctx.accounts.global_state.receive_address {
                return err!(ErrorCode::ConstraintExecutable);
            }
            let amount = ctx.accounts.global_state.s_nft_price;

            // Create the transfer instruction
            let transfer_instruction = system_instruction::transfer(from_account.key, to_account.key, amount);

            // Invoke the transfer instruction
            anchor_lang::solana_program::program::invoke_signed(
                &transfer_instruction,
                &[
                    from_account.to_account_info(),
                    to_account.clone(),
                    ctx.accounts.system_program.to_account_info(),
                ],
                &[],
            )?;     
        }
        let seed = "mint_".to_string() + &ix_args.nft_name;
        // PDA signer seeds
        let signer_seeds: &[&[&[u8]]] = &[&[seed.as_ref(), &[*ctx.bumps.get("mint_account").unwrap()]]];

        // Invoke the mint_to instruction on the token program
        mint_to(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.mint_account.to_account_info(),
                    to: ctx.accounts.associated_token_account.to_account_info(),
                    authority: ctx.accounts.mint_account.to_account_info(), // PDA mint authority, required as signer
                },
            )
            .with_signer(signer_seeds), // using PDA to sign
            1, // Only one
        )?;
        let event = MintNFTEvent{
            user: ctx.accounts.payer.key(),
            nonce: ix_args.nonce.clone(),
            nft_name: ix_args.nft_name.clone(),
            nft_type: ix_args.nft_type.clone(),
            amount: 1
        };
        emit!(event);
        msg!("{:?}", event);
        Ok(()) 
    }
}

#[account]
pub struct GlobalState {
    pub owner: Pubkey,
    pub receive_address: Pubkey,
    pub s_nft_price: u64,
}

#[account]
pub struct ClaimAccount {
    pub nonce: u64,
    pub user: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone, Debug)]
pub struct CreateNFTArgs {
    pub nft_name: String,
    pub nft_symbol: String,
    pub nft_uri: String, 
}

#[derive(AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone, Debug)]
pub struct ReceiveNFTArgs {
    pub nonce: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Eq, PartialEq, Clone, Debug)]
pub struct SynthesisNFTArgs {
    pub nft_name: String,
    pub nft_type: String,
    pub nonce: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        seeds = [b"global"],
        bump,
        space = 8 + size_of::<GlobalState>(),
    )]
    pub global_state: Account<'info, GlobalState>,

    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct UpdateGlobalState<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"global"],
        bump,
    )]
    pub global_state: Account<'info, GlobalState>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(ix_args: CreateNFTArgs)]
pub struct CreateNFT<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        seeds = [format!("mint_{}", ix_args.nft_name).as_ref()],
        bump,
        payer = payer,
        mint::decimals = 0,
        mint::authority = mint_account.key(),
    )]
    pub mint_account: Account<'info, Mint>,

    /// CHECK:
    #[account(
        mut,
        address=find_metadata_account(&mint_account.key()).0
    )]
    pub metadata_account: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"global"],
        bump,
    )]
    pub global_state: Account<'info, GlobalState>,
    pub token_program: Program<'info, Token>,
    pub token_metadata_program: Program<'info, Metadata>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    
}

#[derive(Accounts)]
#[instruction(ix_args: ReceiveNFTArgs)]
pub struct ReceiveNFTFragment<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [b"global"],
        bump
    )]
    pub global_state: Account<'info, GlobalState>,

    #[account(
        init,
        seeds = [format!("claim_{}", ix_args.nonce).as_ref()],
        bump,
        payer = payer,
        space = 8 + size_of::<ClaimAccount>(),
    )]
    pub claim_account: Account<'info, ClaimAccount>,

    pub system_program: Program<'info, System>,
    /// CHECK: This is not dangerous because we explicitly check the id
    #[account(address = instructions_sysvar_module::ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
#[instruction(ix_args: SynthesisNFTArgs)]
pub struct SynthesisNFT<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: check by global state
    #[account(mut)]
    pub to: AccountInfo<'info>,

    // Mint account address is a PDA
    #[account(
        mut,
        seeds = [format!("mint_{}", ix_args.nft_name).as_ref()],
        bump
    )]
    pub mint_account: Account<'info, Mint>,

    #[account(
        init,
        seeds = [format!("claim_{}", ix_args.nonce).as_ref()],
        bump,
        payer = payer,
        space = 8 + size_of::<ClaimAccount>(),
    )]
    pub claim_account: Account<'info, ClaimAccount>,

    // Create Associated Token Account, if needed
    // This is the account that will hold the minted tokens
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint_account,
        associated_token::authority = payer,
    )]
    pub associated_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"global"],
        bump
    )]
    pub global_state: Account<'info, GlobalState>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: This is not dangerous because we explicitly check the id
    #[account(address = instructions_sysvar_module::ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

#[derive(Debug)]
#[event]
pub struct CreateNFTEvent {
    pub nft_name: String,
    pub nft_symbol: String,
    pub nft_uri: String,
}

#[derive(Debug)]
#[event]
pub struct NFTFragmentEvent {
    #[index]
    pub user: Pubkey,
    pub nonce: u64,
    pub nft_name: String,
    pub nft_metadata: String,
    pub amount: u64,
}

#[derive(Debug)]
#[event]
pub struct MintNFTEvent {
    #[index]
    pub user: Pubkey,
    pub nonce: u64,
    pub nft_name: String,
    pub nft_type: String,
    pub amount: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Debug, PartialEq, Eq)]
pub struct ClaimNFT {
    pub customer: Pubkey,
    pub event_type: String,
    pub nonce: u64,
    pub amount: u64,
    pub nft_name: String,
    pub nft_type: String,
    pub nft_metadata: String,
}

fn validate_ed25519_ix(ix: &anchor_lang::solana_program::instruction::Instruction) -> bool {
    if ix.program_id != ED25519_PROGRAM_ID || ix.accounts.len() != 0 {
        return false;
    }
    let ix_data = &ix.data;
    let public_key_offset = &ix_data[6..=7];
    let exp_public_key_offset = u16::try_from(EXPECTED_PUBLIC_KEY_OFFSET)
        .unwrap()
        .to_le_bytes();
    let expected_num_signatures: u8 = 1;
    return public_key_offset       == &exp_public_key_offset                        && // pulic_key in expected offset (16)
        &[ix_data[0]]           == &expected_num_signatures.to_le_bytes()        && // num_signatures is 1
        &[ix_data[1]]           == &[0]                                          && // padding is 0
        &ix_data[4..=5]         == &u16::MAX.to_le_bytes()                       && // signature_instruction_index is not defined by user (default value)
        &ix_data[8..=9]         == &u16::MAX.to_le_bytes()                       && // public_key_instruction_index is not defined by user (default value)
        &ix_data[14..=15]       == &u16::MAX.to_le_bytes(); // message_instruction_index is not defined by user (default value)
}
