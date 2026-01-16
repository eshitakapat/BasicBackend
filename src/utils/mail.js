import Mailgen from "mailgen";

const emailVerificationMailgenContent = (username , verificationUrl) => {
    return {
        body:{
            name: username,
            intro: "Welcome",
            action:{
              instructions: 'To get started with Mailgen, please click here:',
              button: {
               color: '#22BC66', 
               text: 'Confirm your account',
               link: verificationUrl
              }  
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }

}

const forgotPasswordMailgenContent = (username , passwordResetUrl) => {
    return {
        body:{
            name: username,
            intro: "we got a request to reset the password of your account",
            action:{
              instructions: 'To reset your password click on the following button or link',
              button: {
               color: '#22BC66', 
               text: 'Reset password',
               link: passwordResetUrl
              }  
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }

}

export {
    emailVerificationMailgenContent,
    forgotPasswordMailgenContent
};